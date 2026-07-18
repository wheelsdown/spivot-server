// Package logging contains shared logging helpers.
package logging

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// AccessResponseWriter wraps an [http.ResponseWriter] to record the
// status code and byte count an access log line reports. It forwards
// the optional interfaces the underlying writer may implement
// (Flusher, Hijacker, Pusher, ReaderFrom) so wrapping does not
// silently disable streaming, websockets, or sendfile.
type AccessResponseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int64
}

// NewAccessResponseWriter wraps w for access-log capture.
func NewAccessResponseWriter(w http.ResponseWriter) *AccessResponseWriter {
	return &AccessResponseWriter{ResponseWriter: w}
}

// StatusCode returns the response status, defaulting to 200 when the
// handler never called WriteHeader explicitly.
func (w *AccessResponseWriter) StatusCode() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

// BytesWritten returns the number of body bytes written so far.
func (w *AccessResponseWriter) BytesWritten() int64 {
	return w.bytes
}

// WriteHeader records the status code and forwards it.
func (w *AccessResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// Write forwards the body bytes, counting them and recording the
// implicit 200 on a header-less first write.
func (w *AccessResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

// Flush forwards to the underlying [http.Flusher] when implemented.
func (w *AccessResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.statusCode == 0 {
			w.statusCode = http.StatusOK
		}
		flusher.Flush()
	}
}

// Hijack forwards to the underlying [http.Hijacker], or reports
// [http.ErrNotSupported] when the writer cannot hijack.
func (w *AccessResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

// Push forwards to the underlying [http.Pusher], or reports
// [http.ErrNotSupported] when the writer cannot push.
func (w *AccessResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

// ReadFrom forwards to the underlying [io.ReaderFrom] when
// implemented (preserving sendfile), falling back to [io.Copy]
// through Write so the byte count stays accurate.
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

// Unwrap exposes the underlying writer for [http.ResponseController].
func (w *AccessResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
