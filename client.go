package resty

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/runner-mei/errors"
	"github.com/runner-mei/resty/tracing"
)

const (
	charsetUTF8 = "charset=UTF-8"
	// PROPFIND Method can be used on collection and property resources.
	PROPFIND = "PROPFIND"
)

// MIME types
const (
	MIMEApplicationJSON                  = "application/json"
	MIMEApplicationJSONCharsetUTF8       = MIMEApplicationJSON + "; " + charsetUTF8
	MIMEApplicationJavaScript            = "application/javascript"
	MIMEApplicationJavaScriptCharsetUTF8 = MIMEApplicationJavaScript + "; " + charsetUTF8
	MIMEApplicationXML                   = "application/xml"
	MIMEApplicationXMLCharsetUTF8        = MIMEApplicationXML + "; " + charsetUTF8
	MIMETextXML                          = "text/xml"
	MIMETextXMLCharsetUTF8               = MIMETextXML + "; " + charsetUTF8
	MIMEApplicationForm                  = "application/x-www-form-urlencoded"
	MIMEApplicationProtobuf              = "application/protobuf"
	MIMEApplicationMsgpack               = "application/msgpack"
	MIMETextHTML                         = "text/html"
	MIMETextHTMLCharsetUTF8              = MIMETextHTML + "; " + charsetUTF8
	MIMETextPlain                        = "text/plain"
	MIMETextPlainCharsetUTF8             = MIMETextPlain + "; " + charsetUTF8
	MIMEMultipartForm                    = "multipart/form-data"
	MIMEOctetStream                      = "application/octet-stream"

	HeaderContentType   = "Content-Type"
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
)

type HTTPError = errors.HTTPError

var TimeFormat = time.RFC3339
var ErrBadArgument = errors.ErrBadArgument
var WithHTTPCode = errors.WithHTTPCode
var Wrap = errors.Wrap

var DefaultPool = &PooledBuffers{}

func init() {
	DefaultPool.Pool.New = func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 1024))
	}
}

type MemoryPool interface {
	Get() *bytes.Buffer
	Put(*bytes.Buffer)
}

type PooledBuffers struct {
	Pool sync.Pool
}

func (pool *PooledBuffers) Get() *bytes.Buffer {
	return pool.Pool.Get().(*bytes.Buffer)
}

func (pool *PooledBuffers) Put(b *bytes.Buffer) {
	b.Reset()
	pool.Pool.Put(b)
}

type URLFunc func(u *url.URL) error

type AuthFunc func(context.Context, *Request, bool) (string, string, error)

type ResponseFunc func(context.Context, *http.Request, *http.Response) HTTPError

func Unmarshal(result interface{}, cached *bytes.Buffer) ResponseFunc {
	return ResponseFunc(func(ctx context.Context, req *http.Request, resp *http.Response) HTTPError {
		if cached == nil {
			cached = DefaultPool.Get()
			defer DefaultPool.Put(cached)
		} else {
			cached.Reset()
		}

		_, e := io.Copy(cached, resp.Body)
		if e != nil {
			return WithHTTPCode(11, Wrap(e, "request '"+req.Method+"' is ok and read response fail"))
		}

		e = json.Unmarshal(cached.Bytes(), result)
		if e != nil {
			return WithHTTPCode(12, Wrap(e, "request '"+req.Method+"' is ok and unmarshal response fail\r\n"+
				cached.String()))
		}

		return nil
	})
}

type ImmutableProxy interface {
	Clone() *Proxy
	New(urlStr ...string) *Request
}

func Must(pxy *Proxy, err error) *Proxy {
	if err != nil {
		panic(err)
	}
	return pxy
}

func New(urlStr string) (*Proxy, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	var queryParams = url.Values{}
	for key, values := range u.Query() {
		queryParams[key] = values
	}
	u.RawQuery = ""

	return &Proxy{
		MemoryPool:  DefaultPool,
		Client:      http.DefaultClient,
		TimeFormat:  TimeFormat,
		u:           *u,
		queryParams: queryParams,
		headers:     url.Values{},
	}, nil
}

type Proxy struct {
	Tracer        opentracing.Tracer
	MemoryPool    MemoryPool
	Client        *http.Client
	TimeFormat    string
	jsonUseNumber bool
	authWith      AuthFunc
	urlFor        URLFunc
	u             url.URL
	queryParams   url.Values
	headers       url.Values
}

func (px *Proxy) Clone() *Proxy {
	copyed := new(Proxy)
	*copyed = *px
	copyed.queryParams = url.Values{}
	for key, value := range px.queryParams {
		copyed.queryParams[key] = value
	}

	copyed.headers = url.Values{}
	for key, value := range px.headers {
		copyed.headers[key] = value
	}
	return copyed
}
func (px *Proxy) Join(urlStr ...string) *Proxy {
	px.u.Path = JoinWith(px.u.Path, urlStr)
	return px
}
func (px *Proxy) SetTracer(tracer opentracing.Tracer) *Proxy {
	px.Tracer = tracer
	return px
}
func (px *Proxy) JSONUseNumber() *Proxy {
	px.jsonUseNumber = true
	return px
}
func (px *Proxy) SetURLFor(cb URLFunc) *Proxy {
	px.urlFor = cb
	return px
}
func (px *Proxy) AuthWith(authWith AuthFunc) *Proxy {
	px.authWith = authWith
	return px
}
func (px *Proxy) SetHeader(key, value string) *Proxy {
	px.headers.Set(key, value)
	return px
}
func (px *Proxy) AddHeader(key, value string) *Proxy {
	px.headers.Add(key, value)
	return px
}
func (px *Proxy) SetParam(key, value string) *Proxy {
	px.queryParams.Set(key, value)
	return px
}
func (px *Proxy) AddParam(key, value string) *Proxy {
	px.queryParams.Add(key, value)
	return px
}
func (px *Proxy) SetContentType(contentType string) *Proxy {
	px.headers.Set(HeaderContentType, contentType)
	return px
}

func (proxy *Proxy) Release(request *Request) {}

func (proxy *Proxy) New(urlStr ...string) *Request {
	r := &Request{
		tracer:        proxy.Tracer,
		proxy:         proxy,
		memoryPool:    proxy.MemoryPool,
		jsonUseNumber: proxy.jsonUseNumber,
		authWith:      proxy.authWith,
		urlFor:        proxy.urlFor,
		u:             proxy.u,
		queryParams:   url.Values{},
		headers:       url.Values{},
	}

	for key, values := range proxy.queryParams {
		r.queryParams[key] = values
	}
	for key, values := range proxy.headers {
		r.headers[key] = values
	}

	if len(urlStr) > 0 {
		u, err := url.Parse(urlStr[0])
		if err != nil {
			panic(err)
		}
		if u.Scheme != "" {
			r.u = *u
			for key, values := range u.Query() {
				r.queryParams[key] = values
			}

			r.u.Path = JoinWith(r.u.Path, urlStr[1:])
		} else {
			r.u.Path = JoinWith(r.u.Path, urlStr)
		}
	}
	return r
}

type Request struct {
	tracer        opentracing.Tracer
	proxy         *Proxy
	memoryPool    MemoryPool
	jsonUseNumber bool
	authWith      AuthFunc
	urlFor        URLFunc
	u             url.URL
	queryParams   url.Values
	headers       url.Values
	requestBody   interface{}
	exceptedCode  int
	responseBody  interface{}
}

func (r *Request) Clone() *Request {
	copyed := new(Request)
	*copyed = *r

	if copyed.u.User != nil {
		user := copyed.u.User.Username()
		pwd, isSet := copyed.u.User.Password()

		if isSet {
			copyed.u.User = url.UserPassword(user, pwd)
		} else {
			copyed.u.User = url.User(user)
		}
	}

	for key, values := range r.queryParams {
		copyed.queryParams[key] = values
	}
	for key, values := range r.headers {
		copyed.headers[key] = values
	}
	return copyed
}
func (r *Request) SetMemoryPool(pool MemoryPool) *Request {
	r.memoryPool = pool
	return r
}
func (r *Request) SetURL(urlStr string) *Request {
	if urlStr != "" {
		u, err := url.Parse(urlStr)
		if err != nil {
			panic(err)
		}

		if u.Scheme != "" {
			r.u = *u
		} else {
			r.u.Path = Join(r.u.Path, u.Path)
		}

		for key, values := range u.Query() {
			r.queryParams[key] = values
		}
	}
	return r
}
func (r *Request) AuthWith(authWith AuthFunc) *Request {
	r.authWith = authWith
	return r
}
func (r *Request) RequestURL() string {
	return r.u.String()
}
func (r *Request) JoinURL(urlStr ...string) *Request {
	r.u.Path = JoinWith(r.u.Path, urlStr)
	return r
}
func (r *Request) SetTracer(tracer opentracing.Tracer) *Request {
	r.tracer = tracer
	return r
}
func (r *Request) SetURLFor(cb URLFunc) *Request {
	r.urlFor = cb
	return r
}
func (r *Request) JSONUseNumber() *Request {
	r.jsonUseNumber = true
	return r
}
func (r *Request) SetHeader(key, value string) *Request {
	r.headers.Set(key, value)
	return r
}
func (r *Request) AddHeader(key, value string) *Request {
	r.headers.Add(key, value)
	return r
}
func (r *Request) SetParam(key, value string) *Request {
	r.queryParams.Set(key, value)
	return r
}
func (r *Request) AddParam(key, value string) *Request {
	r.queryParams.Add(key, value)
	return r
}
func (r *Request) AddParams(values url.Values) *Request {
	for key, value := range values {
		r.queryParams[key] = append(r.queryParams[key], value...)
	}
	return r
}
func (r *Request) SetParams(values url.Values) *Request {
	for key, value := range values {
		r.queryParams[key] = value
	}
	return r
}
func (r *Request) AddParamValues(values map[string]string) *Request {
	for key, value := range values {
		r.queryParams.Add(key, value)
	}
	return r
}
func (r *Request) SetParamValues(values map[string]string) *Request {
	for key, value := range values {
		r.queryParams.Set(key, value)
	}
	return r
}
func (r *Request) SetBody(body interface{}) *Request {
	r.requestBody = body
	return r
}
func (r *Request) Result(body interface{}) *Request {
	r.responseBody = body
	return r
}
func (r *Request) ExceptedCode(code int) *Request {
	r.exceptedCode = code
	return r
}
func (r *Request) GET(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "GET")
}
func (r *Request) POST(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "POST")
}
func (r *Request) PUT(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "PUT")
}
func (r *Request) CONNECT(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "CONNECT")
}
func (r *Request) DELETE(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "DELETE")
}
func (r *Request) HEAD(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "HEAD")
}
func (r *Request) OPTIONS(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "OPTIONS")
}
func (r *Request) PATCH(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "PATCH")
}
func (r *Request) TRACE(ctx context.Context) HTTPError {
	return r.invokeWithAuth(ctx, "TRACE")
}
func (r *Request) Do(ctx context.Context, method string) HTTPError {
	return r.invokeWithAuth(ctx, method)
}

func isUnauthorized(err HTTPError) bool {
	return err.HTTPCode() == http.StatusUnauthorized
}

func (r *Request) invokeWithAuth(ctx context.Context, method string) HTTPError {
	if r.authWith == nil {
		return r.invoke(ctx, method)
	}

	key, value, e := r.authWith(ctx, r, false)
	if e != nil {
		if he, ok := e.(HTTPError); ok {
			return he
		}
		return WithHTTPCode(11, errors.Wrap(e, "url_for"))
	}
	r = r.SetParam(key, value)

	err := r.invoke(ctx, method)
	if err == nil || !isUnauthorized(err) {
		return err
	}

	key, value, e = r.authWith(ctx, r, true)
	if e != nil {
		if he, ok := e.(HTTPError); ok {
			return he
		}
		return WithHTTPCode(11, e)
	}
	r = r.SetParam(key, value)

	return r.invoke(ctx, method)
}

func (r *Request) invoke(ctx context.Context, method string) HTTPError {
	var req *http.Request

	var body io.Reader
	if r.requestBody != nil && method != "GET" {
		switch value := r.requestBody.(type) {
		case []byte:
			body = bytes.NewReader(value)
		case string:
			body = strings.NewReader(value)
		case io.Reader:
			body = value
		default:
			buffer := r.memoryPool.Get()
			e := json.NewEncoder(buffer).Encode(r.requestBody)
			if e != nil {
				return WithHTTPCode(http.StatusBadRequest, e)
			}
			body = buffer
			defer func() {
				r.memoryPool.Put(buffer)
			}()
		}
	}

	if r.urlFor != nil {
		if err := r.urlFor(&r.u); err != nil {
			return WithHTTPCode(11, errors.Wrap(err, "url_for"))
		}
	}

	r.u.RawQuery = r.queryParams.Encode()
	urlStr := r.u.String()
	req, e := http.NewRequest(method, urlStr, body)
	if e != nil {
		return WithHTTPCode(http.StatusBadRequest, e)
	}

	var ht *tracing.Tracer
	if r.tracer != nil {
		ctx, req, ht = tracing.TraceRequest(ctx, r.tracer, req)
		defer ht.Finish()

		ht.Start(req)
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	for key, values := range r.headers {
		req.Header[key] = values
	}

	client := r.proxy.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, e := client.Do(req)
	if e != nil {
		return WithHTTPCode(http.StatusServiceUnavailable, e)
	}

	if ht != nil {
		ht.Stop(resp)
	}

	isOK := false
	if r.exceptedCode == 0 {
		if resp.StatusCode >= http.StatusOK && resp.StatusCode <= 299 {
			isOK = true
		}
	} else if resp.StatusCode == r.exceptedCode {
		isOK = true
	}

	if !isOK {
		var responseBody string

		if nil != resp.Body {
			respBody := r.memoryPool.Get()
			_, e := io.Copy(respBody, resp.Body)
			resp.Body.Close()

			if e != nil {
				responseBody = respBody.String() + "\r\n*************** "
				responseBody += e.Error()
				responseBody += "***************"
			} else {
				responseBody = respBody.String()
			}

			r.memoryPool.Put(respBody)
		}

		if len(responseBody) == 0 {
			return WithHTTPCode(resp.StatusCode, errors.New("request '"+urlStr+"' fail: "+resp.Status+": read_error"))
		}
		return WithHTTPCode(resp.StatusCode, errors.New("request '"+urlStr+"' fail: "+resp.Status+": "+responseBody))
	}

	// Install closing the request body (if any)
	defer func() {
		if nil != resp.Body {
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	if r.responseBody == nil {
		return nil
	}

	switch response := r.responseBody.(type) {
	case ResponseFunc:
		return response(ctx, req, resp)
	case *string:
		var sb strings.Builder
		if _, e = io.Copy(&sb, resp.Body); e != nil {
			return WithHTTPCode(11, Wrap(e, "request '"+method+"' is ok and read response fail"))
		}
		*response = sb.String()
		return nil
	case *[]byte:
		buffer := bytes.NewBuffer(make([]byte, 0, 1024))
		if _, e = io.Copy(buffer, resp.Body); e != nil {
			return WithHTTPCode(11, Wrap(e, "request '"+method+"' is ok and read response fail"))
		}
		*response = buffer.Bytes()
		return nil
	case io.Writer:
		_, e = io.Copy(response, resp.Body)
		if e == nil {
			return nil
		}
		return WithHTTPCode(11, e)
	default:
		if r.jsonUseNumber {
			decoder := json.NewDecoder(resp.Body)
			decoder.UseNumber()
			e = decoder.Decode(response)
			if e != nil {
				return WithHTTPCode(12, Wrap(e, "request '"+method+"' is ok and read response fail"))
			}
			return nil
		}

		buffer := r.memoryPool.Get()
		_, e = io.Copy(buffer, resp.Body)
		if e != nil {
			buffer.Reset()
			r.memoryPool.Put(buffer)
			return WithHTTPCode(11, Wrap(e, "request '"+method+"' is ok and read response fail"))
		}

		e = json.Unmarshal(buffer.Bytes(), response)
		r.memoryPool.Put(buffer)
		if e != nil {
			return WithHTTPCode(12, Wrap(e, "request '"+method+"' is ok and read response fail"))
		}
		return nil
	}
}

// Join 拼接 url
func Join(paths ...string) string {
	switch len(paths) {
	case 0:
		return ""
	case 1:
		return paths[0]
	case 2:
		lastSplash := strings.HasSuffix(paths[0], "/")
		if lastSplash {
			if strings.HasPrefix(paths[1], "/") {
				return paths[0] + paths[1][1:]
			}
			return paths[0] + paths[1]
		} else if strings.HasPrefix(paths[1], "/") {
			return paths[0] + paths[1]
		}
		return paths[0] + "/" + paths[1]
	default:
		return JoinWith(paths[0], paths[1:])
	}
}

// JoinWith 拼接 url
func JoinWith(base string, paths []string) string {
	var buf strings.Builder
	buf.WriteString(base)

	lastSplash := strings.HasSuffix(base, "/")
	for _, pa := range paths {
		if 0 == len(pa) {
			continue
		}

		if lastSplash {
			if '/' == pa[0] {
				buf.WriteString(pa[1:])
			} else {
				buf.WriteString(pa)
			}
		} else {
			if '/' != pa[0] {
				buf.WriteString("/")
			}
			buf.WriteString(pa)
		}

		lastSplash = strings.HasSuffix(pa, "/")
	}
	return buf.String()
}

// func NewRequest(proxy Proxy, urlStr string) Request {
//  return nil
// }

// func ReleaseRequest(proxy Proxy, request Request) {
// }

func NewRequest(proxy *Proxy, urlStr string) *Request {
	return proxy.New(urlStr)
}

func ReleaseRequest(proxy *Proxy, r *Request) {
	proxy.Release(r)
}

var Default = Must(New(""))

func Post(urlStr string, body, result interface{}) HTTPError {
	return Default.New(urlStr).
		SetBody(body).
		Result(result).
		POST(nil)
}

func Get(urlStr string, result interface{}) HTTPError {
	return Default.New(urlStr).
		Result(result).
		GET(nil)
}

func Put(urlStr string, body, result interface{}) HTTPError {
	return Default.New(urlStr).
		SetBody(body).
		Result(result).
		PUT(nil)
}

func Delete(urlStr string, body, result interface{}) HTTPError {
	return Default.New(urlStr).
		SetBody(body).
		Result(result).
		DELETE(nil)
}

func Do(method, urlStr string, body, statusCode int, result interface{}) HTTPError {
	return Default.New(urlStr).
		SetBody(body).
		Result(result).
		Do(nil, method)
}

func RealIP(req *http.Request) string {
	ra := req.RemoteAddr
	if ip := req.Header.Get(HeaderXForwardedFor); ip != "" {
		ra = ip
	} else if ip := req.Header.Get(HeaderXRealIP); ip != "" {
		ra = ip
	} else {
		ra, _, _ = net.SplitHostPort(ra)
	}
	return ra
}
