// Package logging contains shared logging helpers.
package logging

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

type AccessResponseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int64
}

func NewAccessResponseWriter(w http.ResponseWriter) *AccessResponseWriter {
	return &AccessResponseWriter{ResponseWriter: w}
}

func (w *AccessResponseWriter) StatusCode() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

func (w *AccessResponseWriter) BytesWritten() int64 {
	return w.bytes
}

func (w *AccessResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *AccessResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *AccessResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.statusCode == 0 {
			w.statusCode = http.StatusOK
		}
		flusher.Flush()
	}
}

func (w *AccessResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *AccessResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (w *AccessResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		if w.statusCode == 0 {
			w.statusCode = http.StatusOK
		}
		n, err := rf.ReadFrom(src)
		w.bytes += n
		return n, err
	}
	return io.Copy(w, src)
}

func (w *AccessResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
