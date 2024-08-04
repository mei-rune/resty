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

var DefaultTraceOptions = []tracing.ClientOption{
	tracing.ClientTrace(false),
	tracing.InjectSpanContext(true),
}
var TimeFormat = time.RFC3339
var ErrBadArgument = errors.ErrBadArgument
var WithHTTPCode = errors.WithHTTPCode
var Wrap = errors.Wrap
var AsHTTPError = errors.AsHTTPError

var (
	ErrNoContent = WithHTTPCode(errors.New("no content"), http.StatusNoContent*1000+001)
)

func ErrReadResponseFailCode() int {
	return errors.ErrReadResponseFail.HTTPCode()
}

func ErrUnmarshalResponseFailCode() int {
	return errors.ErrUnmarshalResponseFail.HTTPCode()
}

var DefaultPool = &PooledBuffers{}

func init() {
	DefaultPool.Pool.New = func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 1024))
	}
}

type MemoryPool = tracing.MemoryPool

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

type AuthFunc func(context.Context, *Request, bool) (*Request, error)

type ResponseFunc func(context.Context, *http.Request, *http.Response) HTTPError

func Unmarshal(result interface{}, cached *bytes.Buffer) ResponseFunc {
	return ResponseFunc(func(ctx context.Context, req *http.Request, resp *http.Response) HTTPError {
		if cached == nil {
			cached = DefaultPool.Get()
			defer DefaultPool.Put(cached)
		} else {
			cached.Reset()
		}

		// _, e := io.Copy(cached, resp.Body)
		// if e != nil {
		// 	return WithHTTPCode(Wrap(e, "request '"+req.Method+"' is ok and read response fail"), errors.ErrReadResponseFail.HTTPCode())
		// }

		decoder := json.NewDecoder(io.TeeReader(resp.Body, cached))
		decoder.UseNumber()
		e := decoder.Decode(result)
		if e != nil {
			return WithHTTPCode(Wrap(e, "request '"+req.Method+"' is ok and unmarshal response fail\r\n"+
				cached.String()), errors.ErrUnmarshalResponseFail.HTTPCode())
		}
		return nil
	})
}

type ImmutableProxy interface {
	Clone() *Proxy
	New(urlStr ...string) *Request
}

type ImmutableRequest interface {
	Clone() *Request
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
	return NewWith(u)
}

func NewWith(u *url.URL) (*Proxy, error) {
	var queryParams = url.Values{}
	for key, values := range u.Query() {
		queryParams[key] = values
	}
	u.RawQuery = ""

	return &Proxy{
		MemoryPool:  DefaultPool,
		Client:      InsecureHttpClent,
		TimeFormat:  TimeFormat,
		u:           *u,
		queryParams: queryParams,
		headers:     url.Values{},
	}, nil
}

type Proxy struct {
	Tracer        opentracing.Tracer
	traceOptions  []tracing.ClientOption
	MemoryPool    MemoryPool
	Client        *http.Client
	TimeFormat    string
	jsonUseNumber bool
	noBodyInError bool
	errorFunc     ResponseFunc
	authWith      AuthFunc
	urlFor        URLFunc
	u             url.URL
	queryParams   url.Values
	headers       url.Values
	wrapResult    func(body interface{}) ResponseFunc
	trace         func(*http.Client, *http.Request) (*http.Response, error)
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

func (px *Proxy) NoBodyInError() *Proxy {
	px.noBodyInError = true
	return px
}

func (px *Proxy) ErrorFunc(f ResponseFunc) *Proxy {
	px.errorFunc = f
	return px
}

func (px *Proxy) SetTraceFunc(trace func(*http.Client, *http.Request) (*http.Response, error)) *Proxy {
	px.trace = trace
	return px
}

func (px *Proxy) SetTracer(tracer opentracing.Tracer, traceOptions ...tracing.ClientOption) *Proxy {
	px.Tracer = tracer
	px.traceOptions = traceOptions

	if len(px.traceOptions) == 0 {
		px.traceOptions = DefaultTraceOptions
	}
	return px
}
func (px *Proxy) SetWrapFunc(wrapResult func(body interface{}) ResponseFunc) *Proxy {
	px.wrapResult = wrapResult
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
func (px *Proxy) UnsetHeader(key string) *Proxy {
	px.headers.Del(key)
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
func (px *Proxy) SetParamArray(key string, values []string) *Proxy {
	px.queryParams[key] = values
	return px
}
func (px *Proxy) UnsetParam(key string) *Proxy {
	px.queryParams.Del(key)
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
		traceOptions:  proxy.traceOptions,
		proxy:         proxy,
		memoryPool:    proxy.MemoryPool,
		jsonUseNumber: proxy.jsonUseNumber,
		noBodyInError: proxy.noBodyInError,
		authWith:      proxy.authWith,
		urlFor:        proxy.urlFor,
		u:             proxy.u,
		trace:         proxy.trace,
		errorFunc:     proxy.errorFunc,
		wrapResult:    proxy.wrapResult,
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
			if u.RawQuery == "" && u.Fragment == "" {
				r.u.Path = JoinWith(r.u.Path, urlStr)
			} else {

				for key, values := range u.Query() {
					r.queryParams[key] = values
				}
				if u.Fragment != "" && r.u.Fragment == "" {
					r.u.Fragment = u.Fragment
				}
				r.u.Path = Join(r.u.Path, u.Path)
				r.u.Path = JoinWith(r.u.Path, urlStr[1:])
			}
		}
	}
	return r
}

type Request struct {
	tracer        opentracing.Tracer
	traceOptions  []tracing.ClientOption
	proxy         *Proxy
	memoryPool    MemoryPool
	noBodyInError bool
	jsonUseNumber bool
	authWith      AuthFunc
	urlFor        URLFunc
	u             url.URL
	queryParams   url.Values
	headers       url.Values
	cookies       []*http.Cookie
	requestBody   interface{}
	exceptedCode  int
	responseBody  interface{}
	errorFunc     ResponseFunc
	wrapResult    func(body interface{}) ResponseFunc
	trace         func(*http.Client, *http.Request) (*http.Response, error)
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

	copyed.cookies = make([]*http.Cookie, len(r.cookies))
	copy(copyed.cookies, r.cookies)
	return copyed
}
func (r *Request) SetMemoryPool(pool MemoryPool) *Request {
	r.memoryPool = pool
	return r
}

func (r *Request) SetAbsURL(urlStr string) *Request {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}

	if u.Scheme != "" {
		r.u = *u
	} else {
		r.u.Path = u.Path
		r.u.Fragment = u.Fragment
		r.u.Opaque = u.Opaque
	}

	for key, values := range u.Query() {
		r.queryParams[key] = values
	}
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

func (r *Request) SetTraceFunc(trace func(*http.Client, *http.Request) (*http.Response, error)) *Request {
	r.trace = trace
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
func (r *Request) SetWrapFunc(wrapResult func(body interface{}) ResponseFunc) *Request {
	r.wrapResult = wrapResult
	return r
}
func (r *Request) SetTracer(tracer opentracing.Tracer, traceOptions ...tracing.ClientOption) *Request {
	r.tracer = tracer
	r.traceOptions = traceOptions
	if len(r.traceOptions) == 0 {
		r.traceOptions = DefaultTraceOptions
	}
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
func (r *Request) UnsetHeader(key string) *Request {
	r.headers.Del(key)
	return r
}
func (r *Request) AddHeader(key, value string) *Request {
	r.headers.Add(key, value)
	return r
}
func (r *Request) SetRawQuery(query string) *Request {
	if query == "" || query == "?" {
		return r
	}
	params, _ := url.ParseQuery(query)
	return r.SetParams(params)
}

func (r *Request) SetParam(key, value string) *Request {
	r.queryParams.Set(key, value)
	return r
}
func (r *Request) UnsetParam(key string) *Request {
	r.queryParams.Del(key)
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
func (r *Request) AddParamsWithPrefix(prefix string, values url.Values) *Request {
	for key, value := range values {
		key = prefix + key
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
func (r *Request) SetParamsWithPrefix(prefix string, values url.Values) *Request {
	for key, value := range values {
		r.queryParams[prefix+key] = value
	}
	return r
}
func (r *Request) SetParamArray(key string, values []string) *Request {
	r.queryParams[key] = values
	return r
}
func (r *Request) AddParamValues(values map[string]string) *Request {
	for key, value := range values {
		r.queryParams.Add(key, value)
	}
	return r
}
func (r *Request) AddParamValuesWithPrefix(prefix string, values map[string]string) *Request {
	for key, value := range values {
		r.queryParams.Add(prefix+key, value)
	}
	return r
}
func (r *Request) SetParamValues(values map[string]string) *Request {
	for key, value := range values {
		r.queryParams.Set(key, value)
	}
	return r
}
func (r *Request) SetParamValuesWithPrefix(prefix string, values map[string]string) *Request {
	for key, value := range values {
		r.queryParams.Set(prefix+key, value)
	}
	return r
}
func (r *Request) AddCookie(cookie *http.Cookie) *Request {
	r.cookies = append(r.cookies, cookie)
	return r
}
func (r *Request) SetBody(body interface{}) *Request {
	r.requestBody = body
	return r
}
func (r *Request) Result(body interface{}) *Request {
	if r.wrapResult != nil {
		r.responseBody = r.wrapResult(body)
	} else {
		r.responseBody = body
	}
	return r
}
func (r *Request) ResultFunc(f ResponseFunc) *Request {
	r.responseBody = f
	return r
}
func (r *Request) ErrorFunc(f ResponseFunc) *Request {
	r.errorFunc = f
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

	rr, e := r.authWith(ctx, r, false)
	if e != nil {
		if he, ok := AsHTTPError(e); ok {
			return he
		}
		return WithHTTPCode(Wrap(e, "login fail"), errors.ErrReadResponseFail.HTTPCode())
	}

	err := rr.invoke(ctx, method)
	if err == nil || !isUnauthorized(err) {
		return err
	}

	rr, e = r.authWith(ctx, r, true)
	if e != nil {
		if he, ok := AsHTTPError(e); ok {
			return he
		}

		return WithHTTPCode(Wrap(e, "login fail"), errors.ErrReadResponseFail.HTTPCode())
	}

	return rr.invoke(ctx, method)
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
				return WithHTTPCode(e, http.StatusBadRequest)
			}
			body = buffer
			defer func() {
				r.memoryPool.Put(buffer)
			}()
		}
	}

	if r.urlFor != nil {
		if err := r.urlFor(&r.u); err != nil {
			return WithHTTPCode(Wrap(err, "generate url fail"), http.StatusBadRequest)
		}
	}
	callbacks := CallbacksFromContext(ctx)
	if callbacks != nil && callbacks.OnBefore != nil {
		callbacks.OnBefore(ctx, r)
	}

	r.u.RawQuery = r.queryParams.Encode()
	urlStr := r.u.String()
	req, e := http.NewRequest(method, urlStr, body)
	if e != nil {
		return WithHTTPCode(e, http.StatusBadRequest)
	}

	var ht *tracing.Tracer
	if r.tracer != nil {
		ctx, req, ht = tracing.TraceRequest(ctx, r.tracer, req, r.traceOptions...)
		defer ht.Finish()

		ht.Start(req)
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	for key, values := range r.headers {
		req.Header[key] = values
	}

	for _, cookie := range r.cookies {
		req.AddCookie(cookie)
	}

	client := r.proxy.Client
	if client == nil {
		client = InsecureHttpClent // http.DefaultClient
	}

	var resp *http.Response
	if r.trace != nil {
		resp, e = r.trace(client, req)
	} else {
		resp, e = client.Do(req)
	}

	if e != nil {
		return WithHTTPCode(e, http.StatusServiceUnavailable)
	}
	if callbacks != nil && callbacks.OnAfter != nil {
		callbacks.OnAfter(ctx, req, resp)
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

	// Install closing the request body (if any)
	bodyCloser := resp.Body
	defer func() {
		if bodyCloser != nil {
			io.Copy(ioutil.Discard, bodyCloser)
			bodyCloser.Close()
		}
	}()

	if !isOK {
		if r.errorFunc != nil {
			return r.errorFunc(ctx, req, resp)
		}

		var responseBody string

		if !r.noBodyInError && nil != resp.Body {
			respBody := r.memoryPool.Get()
			_, e := io.Copy(respBody, resp.Body)

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
			return WithHTTPCode(errors.New("request '"+urlStr+"' fail: "+resp.Status+": read_error"), resp.StatusCode)
		}
		return WithHTTPCode(errors.New("request '"+urlStr+"' fail: "+resp.Status+": "+responseBody), resp.StatusCode)
	}

	if r.responseBody == nil {
		return nil
	}

	if resp.StatusCode == http.StatusNoContent {
		return errors.ErrNoContent
	}

	switch response := r.responseBody.(type) {
	case ResponseFunc:
		return response(ctx, req, resp)
	case *string:
		var sb strings.Builder
		if _, e = io.Copy(&sb, resp.Body); e != nil {
			return WithHTTPCode(Wrap(e, "request '"+method+"' is ok and read response fail"), errors.ErrReadResponseFail.HTTPCode())
		}
		*response = sb.String()
		return nil
	case *[]byte:
		buffer := bytes.NewBuffer(make([]byte, 0, 1024))
		if _, e = io.Copy(buffer, resp.Body); e != nil {
			return WithHTTPCode(Wrap(e, "request '"+method+"' is ok and read response fail"), errors.ErrReadResponseFail.HTTPCode())
		}
		*response = buffer.Bytes()
		return nil
	case io.Writer:
		_, e = io.Copy(response, resp.Body)
		if e == nil {
			return nil
		}
		return WithHTTPCode(Wrap(e, "request '"+method+"' is ok and read response fail"), errors.ErrReadResponseFail.HTTPCode())
	default:
		if r.jsonUseNumber {
			decoder := json.NewDecoder(resp.Body)
			decoder.UseNumber()
			e = decoder.Decode(response)
			if e != nil {
				return WithHTTPCode(Wrap(e, "request '"+method+"' is ok and read response fail"), errors.ErrUnmarshalResponseFail.HTTPCode())
			}
			return nil
		}

		buffer := r.memoryPool.Get()
		_, e = io.Copy(buffer, resp.Body)
		if e != nil {
			buffer.Reset()
			r.memoryPool.Put(buffer)
			return WithHTTPCode(Wrap(e, "request '"+method+"' is ok and read response fail"), errors.ErrReadResponseFail.HTTPCode())
		}

		e = json.Unmarshal(buffer.Bytes(), response)
		r.memoryPool.Put(buffer)
		if e != nil {
			return WithHTTPCode(Wrap(e, "request '"+method+"' is ok and read response fail"), errors.ErrUnmarshalResponseFail.HTTPCode())
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

var Default = Must(New("")).
	SetHeader(HeaderContentType, MIMEApplicationJSONCharsetUTF8)

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
