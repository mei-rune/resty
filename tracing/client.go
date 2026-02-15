package tracing

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

type contextKey int

const (
	keyTracer contextKey = iota
)

const defaultComponentName = "net/http"

// Transport wraps a RoundTripper. If a request is being traced with
// Tracer, Transport will inject the current span into the headers,
// and set HTTP related tags on the span.
type Transport struct {
	// The actual RoundTripper to use for the request. A nil
	// RoundTripper defaults to http.DefaultTransport.
	http.RoundTripper
}

type clientOptions struct {
	operationName            string
	componentName            string
	disableClientTrace       bool
	disableInjectSpanContext bool
	spanObserver             func(span trace.Span, r *http.Request)
}

// ClientOption contols the behavior of TraceRequest.
type ClientOption func(*clientOptions)

// OperationName returns a ClientOption that sets the operation
// name for the client-side span.
func OperationName(operationName string) ClientOption {
	return func(options *clientOptions) {
		options.operationName = operationName
	}
}

// ComponentName returns a ClientOption that sets the component
// name for the client-side span.
func ComponentName(componentName string) ClientOption {
	return func(options *clientOptions) {
		options.componentName = componentName
	}
}

// ClientTrace returns a ClientOption that turns on or off
// extra instrumentation via httptrace.WithClientTrace.
func ClientTrace(enabled bool) ClientOption {
	return func(options *clientOptions) {
		options.disableClientTrace = !enabled
	}
}

// InjectSpanContext returns a ClientOption that turns on or off
// injection of the Span context in the request HTTP headers.
// If this option is not used, the default behaviour is to
// inject the span context.
func InjectSpanContext(enabled bool) ClientOption {
	return func(options *clientOptions) {
		options.disableInjectSpanContext = !enabled
	}
}

// ClientSpanObserver returns a ClientOption that observes the span
// for the client-side span.
func ClientSpanObserver(f func(span trace.Span, r *http.Request)) ClientOption {
	return func(options *clientOptions) {
		options.spanObserver = f
	}
}

// TraceRequest adds a ClientTracer to req, tracing the request and
// all requests caused due to redirects. When tracing requests this
// way you must also use Transport.
//
// Example:
//
//	func AskGoogle(ctx context.Context) error {
//	    client := &http.Client{Transport: &nethttp.Transport{}}
//	    req, err := http.NewRequest("GET", "http://google.com", nil)
//	    if err != nil {
//	        return err
//	    }
//	    req = req.WithContext(ctx) // extend existing trace, if any
//
//	    req, ht := nethttp.TraceRequest(ctx, tracer, req)
//	    defer ht.Finish()
//
//	    req = req.WithContext(ContextWithTracer(req.Context(), ht))
//	    res, err := client.Do(req)
//	    if err != nil {
//	        return err
//	    }
//	    res.Body.Close()
//	    return nil
//	}
func TraceRequest(ctx context.Context, tp trace.TracerProvider, req *http.Request, options ...ClientOption) (context.Context, *http.Request, *Tracer) {
	opts := &clientOptions{
		spanObserver: func(_ trace.Span, _ *http.Request) {},
	}
	for _, opt := range options {
		opt(opts)
	}
	ht := &Tracer{tp: tp, opts: opts}
	if !opts.disableClientTrace {
		if ctx == nil {
			ctx = context.Background()
		}
		ctx = httptrace.WithClientTrace(ctx, ht.clientTrace())
	}
	return ctx, req, ht
}

type closeTracker struct {
	io.ReadCloser
	sp trace.Span
}

func (c closeTracker) Close() error {
	err := c.ReadCloser.Close()
	c.sp.AddEvent("ClosedBody")
	c.sp.End()
	return err
}

func ContextWithTracer(ctx context.Context, ht *Tracer) context.Context {
	return context.WithValue(ctx, keyTracer, ht)
}

// TracerFromRequest retrieves the Tracer from the request. If the request does
// not have a Tracer it will return nil.
func TracerFromRequest(req *http.Request) *Tracer {
	tr, ok := req.Context().Value(keyTracer).(*Tracer)
	if !ok {
		return nil
	}
	return tr
}

// RoundTrip implements the RoundTripper interface.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := t.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}
	tracer := TracerFromRequest(req)
	if tracer == nil {
		return rt.RoundTrip(req)
	}

	tracer.Start(req)

	resp, err := rt.RoundTrip(req)

	if err != nil {
		tracer.sp.End()
		return resp, err
	}

	tracer.Stop(resp)
	return resp, nil
}

// Tracer holds tracing details for one HTTP request.
type Tracer struct {
	tp   trace.TracerProvider
	root trace.Span
	sp   trace.Span
	opts *clientOptions
}

func (h *Tracer) Start(req *http.Request) trace.Span {
	if h.root == nil {
		operationName := h.opts.operationName
		if operationName == "" {
			operationName = "HTTP Client"
		}
		tr := h.tp.Tracer("resty")
		ctx := req.Context()
		var span trace.Span
		ctx, span = tr.Start(ctx, operationName)
		h.root = span
		req = req.WithContext(ctx)
	}

	tr := h.tp.Tracer("resty")
	ctx := req.Context()
	operationName := "HTTP " + req.Method
	ctx, span := tr.Start(ctx, operationName, trace.WithSpanKind(trace.SpanKindClient))
	h.sp = span

	componentName := h.opts.componentName
	if componentName == "" {
		componentName = defaultComponentName
	}
	h.sp.SetAttributes(
		attribute.String("component", componentName),
		attribute.String("http.method", req.Method),
		attribute.String("http.url", req.URL.String()),
	)
	h.opts.spanObserver(h.sp, req)

	if !h.opts.disableInjectSpanContext {
		propagator := otel.GetTextMapPropagator()
		propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))
	}

	return h.sp
}

func (h *Tracer) Stop(resp *http.Response) {
	h.sp.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
	)
	if resp.StatusCode >= http.StatusInternalServerError {
		h.sp.SetStatus(codes.Error, "HTTP Error")
	}
	if resp.Body == nil {
		h.sp.End()
	} else {
		resp.Body = closeTracker{resp.Body, h.sp}
	}
}

// Finish finishes the span of the traced request.
func (h *Tracer) Finish() {
	if h.root != nil {
		h.root.End()
	}
}

// Span returns the root span of the traced request. This function
// should only be called after the request has been executed.
func (h *Tracer) Span() trace.Span {
	return h.root
}

func (h *Tracer) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn:              h.getConn,
		GotConn:              h.gotConn,
		PutIdleConn:          h.putIdleConn,
		GotFirstResponseByte: h.gotFirstResponseByte,
		Got100Continue:       h.got100Continue,
		DNSStart:             h.dnsStart,
		DNSDone:              h.dnsDone,
		ConnectStart:         h.connectStart,
		ConnectDone:          h.connectDone,
		WroteHeaders:         h.wroteHeaders,
		Wait100Continue:      h.wait100Continue,
		WroteRequest:         h.wroteRequest,
	}
}

func (h *Tracer) getConn(hostPort string) {
	h.sp.SetAttributes(attribute.String("http.url", hostPort))
	h.sp.AddEvent("GetConn")
}

func (h *Tracer) gotConn(info httptrace.GotConnInfo) {
	h.sp.SetAttributes(
		attribute.Bool("net/http.reused", info.Reused),
		attribute.Bool("net/http.was_idle", info.WasIdle),
	)
	h.sp.AddEvent("GotConn")
}

func (h *Tracer) putIdleConn(error) {
	h.sp.AddEvent("PutIdleConn")
}

func (h *Tracer) gotFirstResponseByte() {
	h.sp.AddEvent("GotFirstResponseByte")
}

func (h *Tracer) got100Continue() {
	h.sp.AddEvent("Got100Continue")
}

func (h *Tracer) dnsStart(info httptrace.DNSStartInfo) {
	h.sp.AddEvent("DNSStart", trace.WithAttributes(
		attribute.String("host", info.Host),
	))
}

func (h *Tracer) dnsDone(info httptrace.DNSDoneInfo) {
	attrs := []attribute.KeyValue{}
	for _, addr := range info.Addrs {
		attrs = append(attrs, attribute.String("addr", addr.String()))
	}
	if info.Err != nil {
		attrs = append(attrs, attribute.String("error", info.Err.Error()))
		h.sp.SetStatus(codes.Error, info.Err.Error())
	}
	h.sp.AddEvent("DNSDone", trace.WithAttributes(attrs...))
}

func (h *Tracer) connectStart(network, addr string) {
	h.sp.AddEvent("ConnectStart", trace.WithAttributes(
		attribute.String("network", network),
		attribute.String("addr", addr),
	))
}

func (h *Tracer) connectDone(network, addr string, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("network", network),
		attribute.String("addr", addr),
	}
	if err != nil {
		attrs = append(attrs, attribute.String("error", err.Error()))
		h.sp.SetStatus(codes.Error, err.Error())
		h.sp.AddEvent("ConnectDone", trace.WithAttributes(attrs...))
	} else {
		h.sp.AddEvent("ConnectDone", trace.WithAttributes(attrs...))
	}
}

func (h *Tracer) wroteHeaders() {
	h.sp.AddEvent("WroteHeaders")
}

func (h *Tracer) wait100Continue() {
	h.sp.AddEvent("Wait100Continue")
}

func (h *Tracer) wroteRequest(info httptrace.WroteRequestInfo) {
	if info.Err != nil {
		h.sp.SetStatus(codes.Error, info.Err.Error())
		h.sp.AddEvent("WroteRequest", trace.WithAttributes(
			attribute.String("error", info.Err.Error()),
		))
	} else {
		h.sp.AddEvent("WroteRequest")
	}
}
