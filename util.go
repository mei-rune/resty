package resty

import (
	"context"
	"crypto/tls"
	"net/http"
)

var InsecureHttpTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

var InsecureHttpClent = &http.Client{Transport: InsecureHttpTransport}

//func init() {
//	if t, ok := http.DefaultTransport.(*http.Transport); ok {
//		t.DialContext = netutil.WrapDialContext(t.DialContext)
//		InsecureHttpTransport.DialContext = t.DialContext
//	}
//}

// Callbacks 回调
type Callbacks struct {
	OnBefore func(ctx context.Context, req *Request)
	OnAfter  func(ctx context.Context, req *http.Request, resp *http.Response)
}

type callbackKey struct{}

func (callbackKey) String() string { return "ctx-resty-callbacks" }

var CallbackKey = callbackKey{}

func ContextWithOnBefore(ctx context.Context, onBefore func(ctx context.Context, req *Request)) context.Context {
	callbacks := CallbacksFromContext(ctx)
	if callbacks == nil {
		callbacks = &Callbacks{
			OnBefore: onBefore,
		}
		return context.WithValue(ctx, CallbackKey, callbacks)
	}
	callbacks.OnBefore = onBefore
	return ctx
}

func ContextWithOnAfter(ctx context.Context, onAfter func(ctx context.Context, req *http.Request, resp *http.Response)) context.Context {
	callbacks := CallbacksFromContext(ctx)
	if callbacks == nil {
		callbacks = &Callbacks{
			OnAfter: onAfter,
		}
		return context.WithValue(ctx, CallbackKey, callbacks)
	}
	callbacks.OnAfter = onAfter
	return ctx
}

func ContextWithCallbacks(ctx context.Context, s *Callbacks) context.Context {
	return context.WithValue(ctx, CallbackKey, s)
}

func CallbacksFromContext(ctx context.Context) *Callbacks {
	if ctx == nil {
		return nil
	}
	o := ctx.Value(CallbackKey)
	if o == nil {
		return nil
	}
	values, ok := o.(*Callbacks)
	if !ok {
		return nil
	}
	return values
}
