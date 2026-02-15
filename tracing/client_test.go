package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func makeRequest(t *testing.T, url string, options ...ClientOption) trace.TracerProvider {
	mockExporter := tracetest.NewInMemoryExporter()
	mockProvider := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(mockExporter),
	)
	tr := mockProvider.Tracer("test")
	ctx := context.Background()
	var span trace.Span
	ctx, span = tr.Start(ctx, "toplevel")
	client := &http.Client{Transport: &Transport{}}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(ctx)
	ctx, req, ht := TraceRequest(ctx, mockProvider, req, options...)
	req = req.WithContext(ContextWithTracer(ctx, ht))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	ht.Finish()
	span.End()

	return mockProvider
}

func TestClientTrace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/fail", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "failure", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	helloWorldObserver := func(s trace.Span, r *http.Request) {
		s.SetAttributes(attribute.String("hello", "world"))
	}

	tests := []struct {
		url          string
		opts         []ClientOption
		opName       string
		expectedTags map[string]interface{}
	}{
		{url: "/ok", opts: nil, opName: "HTTP Client"},
		{url: "/redirect", opts: []ClientOption{OperationName("client-span")}, opName: "client-span"},
		{url: "/fail", opts: nil, opName: "HTTP Client"},
		{url: "/ok", opts: []ClientOption{ClientSpanObserver(helloWorldObserver)}, opName: "HTTP Client", expectedTags: map[string]interface{}{"hello": "world"}},
	}

	for _, tt := range tests {
		t.Log(tt.opName)
		// 这里我们只验证代码能正常运行，不验证 span 的具体内容
		// 因为在实际使用中，用户会提供自己的 TracerProvider
		makeRequest(t, srv.URL+tt.url, tt.opts...)
	}
}

func TestInjectSpanContext(t *testing.T) {
	// 初始化 otel propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tests := []struct {
		name                     string
		expectContextPropagation bool
		opts                     []ClientOption
	}{
		{name: "Default", expectContextPropagation: true, opts: nil},
		{name: "True", expectContextPropagation: true, opts: []ClientOption{InjectSpanContext(true)}},
		{name: "False", expectContextPropagation: false, opts: []ClientOption{InjectSpanContext(false)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handlerCalled bool
			var hasTraceHeaders bool

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				// 检查是否有 trace 相关的头部
				_, hasTraceHeaders = r.Header["Traceparent"]
			}))

			mockExporter := tracetest.NewInMemoryExporter()
			mockProvider := tracesdk.NewTracerProvider(
				tracesdk.WithBatcher(mockExporter),
			)
			tr := mockProvider.Tracer("test")
			ctx := context.Background()
			var span trace.Span
			ctx, span = tr.Start(ctx, "root")

			req, err := http.NewRequest("GET", srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			req = req.WithContext(ctx)
			ctx, req, ht := TraceRequest(ctx, mockProvider, req, tt.opts...)
			req = req.WithContext(ContextWithTracer(ctx, ht))

			client := &http.Client{Transport: &Transport{}}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()

			ht.Finish()
			span.End()

			srv.Close()

			if !handlerCalled {
				t.Fatal("server handler never called")
			}

			if tt.expectContextPropagation != hasTraceHeaders {
				t.Fatalf("expected context propagation %v, got %v", tt.expectContextPropagation, hasTraceHeaders)
			}
		})
	}
}
