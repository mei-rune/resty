package tracing

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
)

// Provider specified the interface types must implement to be used as a
// debugging sink. Having multiple such sink implementations allows it to be
// changed externally (for example when running tests).
type DebugProvider interface {
	NewFile(s string) io.WriteCloser
}

// FileProvider implements a debugging provider that creates a real file for
// every call to NewFile. It maintains a list of all files that it creates,
// such that it can close them when its Flush function is called.
type FileDebugProvider struct {
	Path string
}

func (fp *FileDebugProvider) NewFile(p string) io.WriteCloser {
	f, err := os.Create(filepath.Join(fp.Path, p))
	if err != nil {
		panic(err)
	}
	return f
}

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
//
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func drainBody(b io.ReadCloser, buf *bytes.Buffer) (err error) {
	if b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil
	}

	if _, err = buf.ReadFrom(b); err != nil {
		return err
	}
	if err = b.Close(); err != nil {
		return err
	}
	return nil
}

type MemoryPool interface {
	Get() *bytes.Buffer
	Put(*bytes.Buffer)
}

func Trace(dump DebugProvider, memPool MemoryPool) func(*http.Client, *http.Request) (*http.Response, error) {
	var fileid int64
	return func(hc *http.Client, req *http.Request) (*http.Response, error) {
		if dump == nil {
			return hc.Do(req)
		}
		var out = dump.NewFile(strconv.FormatInt(atomic.AddInt64(&fileid, 1), 10) + ".log")
		defer out.Close()

		bs, err := httputil.DumpRequest(req, false)
		if err != nil {
			io.WriteString(out, err.Error())
			io.WriteString(out, "\r\n\r\n")
		} else {
			_, err = out.Write(bs)
			if err != nil {
				io.WriteString(out, err.Error())
				io.WriteString(out, "\r\n\r\n")
			}
		}

		if req.Body != nil {
			req.Body = &teeReader{
				r: req.Body,
				w: out,
			}
		}

		resp, err := hc.Do(req)
		if err != nil {
			io.WriteString(out, "\r\n\r\n")
			io.WriteString(out, err.Error())
			return nil, err
		}
		bs, err = httputil.DumpResponse(resp, false)
		if err != nil {
			io.WriteString(out, err.Error())
		} else {
			_, err = out.Write(bs)
			if err != nil {
				io.WriteString(out, err.Error())
			}
		}

		buf := memPool.Get()
		buf.Reset()
		err = drainBody(resp.Body, buf)
		if err != nil {
			buf.Reset()
			memPool.Put(buf)
			return nil, err
		}

		_, err = out.Write(buf.Bytes())
		if err != nil {
			io.WriteString(out, err.Error())
		}

		resp.Body = ioutil.NopCloser(buf)
		return resp, nil
	}
}

type teeReader struct {
	r io.ReadCloser
	w io.Writer
}

func (t *teeReader) Close() error {
	return t.r.Close()
}
func (t *teeReader) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}
