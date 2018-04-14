package agent

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/syslog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Returns a ReadWriteCloser that may have:
// * [always] writes bytes to a size limited buffer, that can be read from using io.Reader
// * [maybe] writes bytes per line to stderr as DEBUG
// * [maybe] writes bytes per line to each url passed in the list of syslog urls.
//    Syslog urls can be TCP/UDP/TLS, all lines are ERROR level. RFC 5424
//    format is used for each line. Some syslog services (Papertrail) treat entire
//    packets as single lines, without splitting by \n, so we always perform
//    writes to syslog using a line writer.
//
// To prevent write failures from failing the call or any other
// writes, multiWriteCloser ignores errors. Close will flush the line writers
// and close the network connections appropriately, it must be called or conns leak.

// TODO add context plumbing.
// TODO free papertrail account test.
func sysloggersWithBuffer(buf *bytes.Buffer, syslogURLs string, call *call) io.WriteCloser {
	if len(syslogURLs) == 0 {
		return nullReadWriter{}
	}

	// gather all the conns, re-use the line we make in the syslogWriter
	// to write the same bytes to each of the conns.
	var conns []io.WriteCloser

	sinks := strings.Split(syslogURLs, ",")
	for _, s := range sinks {
		conn, err := dialSyslog(strings.TrimSpace(s))
		if err != nil {
			logrus.WithError(err).Warn("failed to setup remote syslog connection to", s)
			continue
		}

		conns = append(conns, conn)
	}

	if len(conns) == 0 {
		return nullReadWriter{}
	}

	// complete chain for this (from top):
	// stderr -> line writer -> syslog writer -> []conns
	return newSyslogWriter(call.ID, call.Path, call.AppID, syslog.LOG_ERR, multiWriteCloser(conns), buf)
}

func dialSyslog(syslogURL string) (io.WriteCloser, error) {
	url, err := url.Parse(syslogURL)
	if err != nil {
		return nil, err
	}

	switch url.Scheme {
	case "udp", "tcp":
		return net.Dial(url.Scheme, syslogURL[6:])
	case "tls":
		return tls.Dial("tcp", syslogURL[6:], &tls.Config{})
	default:
		return nil, fmt.Errorf("Unsupported scheme, please use {tcp|udp|tls}: %s: ", url.Scheme)
	}
}

// syslogWriter prepends a syslog format with call-specific details
// for each data segment provided in Write(). This doesn't use
// log/syslog pkg because we do not need pid for every line (expensive),
// and we have a format that is easier to read than hiding in preamble.
type syslogWriter struct {
	pres []byte
	post []byte
	b    *bytes.Buffer

	// keep Close method to close conns
	io.WriteCloser
}

const severityMask = 0x07
const facilityMask = 0xf8

func newSyslogWriter(call, function, app string, severity syslog.Priority, wc io.WriteCloser, buf *bytes.Buffer) *syslogWriter {
	// Facility = LOG_USER
	pr := (syslog.LOG_USER & facilityMask) | (severity & severityMask)

	// <priority>VERSION ISOTIMESTAMP HOSTNAME APPLICATION PID      MESSAGEID STRUCTURED-DATA MSG
	//
	// and for us:
	// <22>2             ISOTIMESTAMP fn       appID       funcName callID    -               MSG
	// ex:
	//<22>1 2018-02-31T07:42:21Z Fn - - - -  call_id: 123, func_name: rdallman/yodawg, app_id: 123 -- loggo hereo

	// TODO we could use json for structured data and do that whole thing. up to whoever.
	return &syslogWriter{
		pres:        []byte(fmt.Sprintf(`<%d>2 `, pr)),
		post:        []byte(fmt.Sprintf(`fn - - - - call_id: %s, func_name: %s, app_id: %s -- `, call, function, app)),
		b:           buf,
		WriteCloser: wc,
	}
}

func (sw *syslogWriter) Write(p []byte) (int, error) {
	// re-use buffer to write in timestamp hodge podge and reduce writes to
	// the conn by buffering a whole line here before writing to conn.

	buf := sw.b
	buf.Reset()
	buf.Write(sw.pres)
	buf.WriteString(time.Now().UTC().Format(time.RFC3339))
	buf.Write(sw.post)
	buf.Write(p)
	n, err := io.Copy(sw.WriteCloser, buf)
	return int(n), err
}
