package agent

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	bufPool = &sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}
	logPool = &sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}
)

// setupLogger returns an io.ReadWriteCloser which may write to multiple io.Writer's,
// and may be read from the returned io.Reader (singular). After Close is called,
// the Reader is not safe to read from, nor the Writer to write to.
func setupLogger(logger logrus.FieldLogger, maxSize uint64) io.ReadWriteCloser {
	lbuf := bufPool.Get().(*bytes.Buffer)
	dbuf := logPool.Get().(*bytes.Buffer)

	close := func() error {
		// TODO we may want to toss out buffers that grow to grotesque size but meh they will prob get GC'd
		lbuf.Reset()
		dbuf.Reset()
		bufPool.Put(lbuf)
		bufPool.Put(sbuf)
		logPool.Put(dbuf)
		return nil
	}

	// TODO add syslogger here

	// we don't need to limit the log writer, but we do need it to dispense lines
	liners := multiWriteCloser{&nopClose{&logWriter}}
	linew := newLineWriterWithBuffer(lbuf, liners)

	// we don't need to log per line to db, but we do need to limit it
	limitw := &nopCloser{newLimitWriter(int(maxSize), dbuf)}

	mw := multiWriteCloser{linew, limitw, &fCloser{close}}
	return &rwc{mw, dbuf}
}

// implements io.ReadWriteCloser, fmt.Stringer and Bytes()
// TODO WriteString and ReadFrom would be handy to implement,
// ReadFrom is a little involved.
type rwc struct {
	io.WriteCloser

	// buffer is not embedded since it would bypass calls to WriteCloser.Write
	// in cases such as WriteString and ReadFrom
	b *bytes.Buffer
}

func (r *rwc) Read(b []byte) (int, error) { return r.b.Read(b) }
func (r *rwc) String() string             { return r.b.String() }
func (r *rwc) Bytes() []byte              { return r.b.Bytes() }

// implements passthrough Write & closure call in Close
type fCloser struct {
	close func() error
}

func (f *fCloser) Write(b []byte) (int, error) { return len(b), nil }
func (f *fCloser) Close() error                { return f.close() }

type nopCloser struct {
	io.Writer
}

func (n *nopCloser) Close() error { return nil }

type nullReadWriter struct {
	io.ReadCloser
}

func (n nullReadWriter) Close() error {
	return nil
}
func (n nullReadWriter) Read(b []byte) (int, error) {
	return 0, io.EOF
}
func (n nullReadWriter) Write(b []byte) (int, error) {
	return 0, io.EOF
}

// multiWriteCloser ignores all errors from inner writers. you say, oh, this is a bad idea?
// yes, well, we were going to silence them all individually anyway, so let's not be shy about it.
// the main thing we need to ensure is that every close is called, even if another errors.
// XXX(reed): maybe we should log it (for syslog, it may help debug, maybe we just log that one)
type multiWriteCloser []io.WriteCloser

func (m multiWriteCloser) Write(b []byte) (n int, err error) {
	for _, mw := range m {
		mw.Write(b)
	}
	return n, nil
}

func (m multiWriteCloser) Close() (err error) {
	for _, mw := range m {
		mw.Close()
	}
	return nil
}

// logWriter will log (to real stderr) every call to Write as a line. it should
// be wrapped with a lineWriter so that the output makes sense.
type logWriter struct {
	logrus.FieldLogger
}

func (l *logWriter) Write(b []byte) (int, error) {
	l.Debug(string(b))
	return len(b), nil
}

// lineWriter buffers all calls to Write and will call Write
// on the underlying writer once per new line. Close must
// be called to ensure that the buffer is flushed, and a newline
// will be appended in Close if none is present.
type lineWriter struct {
	b *bytes.Buffer
	w io.WriteCloser
}

func newLineWriter(w io.WriteCloser) io.WriteCloser {
	return &lineWriter{b: new(bytes.Buffer), w: w}
}

func newLineWriterWithBuffer(b *bytes.Buffer, w io.WriteCloser) io.WriteCloser {
	return &lineWriter{b: b, w: w}
}

func (li *lineWriter) Write(ogb []byte) (int, error) {
	li.b.Write(ogb) // bytes.Buffer is guaranteed, read it!

	for {
		b := li.b.Bytes()
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break // no more newlines in buffer
		}

		// write in this line and advance buffer past it
		l := b[:i+1]
		ns, err := li.w.Write(l)
		if err != nil {
			return ns, err
		}
		li.b.Next(len(l))
	}

	// technically we wrote all the bytes, so make things appear normal
	return len(ogb), nil
}

func (li *lineWriter) Close() error {
	defer li.w.Close() // MUST close this (after writing last line)

	// flush the remaining bytes in the buffer to underlying writer, adding a
	// newline if needed
	b := li.b.Bytes()
	if len(b) == 0 {
		return nil
	}

	if b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	err := li.w.Write(b)
	return err
}

// io.Writer that allows limiting bytes written to w
// TODO change to use clamp writer, this is dupe code
type limitDiscardWriter struct {
	n, max int
	io.Writer
}

func newLimitWriter(max int, w io.Writer) io.Writer {
	return &limitDiscardWriter{max: max, Writer: w}
}

func (l *limitDiscardWriter) Write(b []byte) (int, error) {
	inpLen := len(b)
	if l.n >= l.max {
		return inpLen, nil
	}

	if l.n+inpLen >= l.max {
		// cut off to prevent gigantic line attack
		b = b[:l.max-l.n]
	}

	n, err := l.Writer.Write(b)
	l.n += n

	if l.n >= l.max {
		// write in truncation message to log once
		l.Writer.Write([]byte(fmt.Sprintf("\n-----max log size %d bytes exceeded, truncating log-----\n", l.max)))
	} else if n != len(b) {
		// Is this truly a partial write? We'll be honest if that's the case.
		return n, err
	}

	// yes, we lie... this is to prevent callers to blow up, we always pretend
	// that we were able to write the entire buffer.
	return inpLen, err
}
