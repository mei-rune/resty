package resty

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
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

type headerKeys struct{}

func (headerKeys) String() string { return "ctx-headers" }

var HeaderKey = headerKeys{}

func ContextWithHeaders(ctx context.Context, s url.Values) context.Context {
	return context.WithValue(ctx, HeaderKey, s)
}

func HeadersFromContext(ctx context.Context) url.Values {
	if ctx == nil {
		return nil
	}
	o := ctx.Value(HeaderKey)
	if o == nil {
		return nil
	}
	values, ok := o.(url.Values)
	if !ok {
		return nil
	}
	return values
}

type queryKeys struct{}

func (queryKeys) String() string { return "ctx-query-str" }

var QueryKey = queryKeys{}

func ContextWithQueryParams(ctx context.Context, s url.Values) context.Context {
	return context.WithValue(ctx, QueryKey, s)
}

func QueryParamsFromContext(ctx context.Context) url.Values {
	if ctx == nil {
		return nil
	}
	o := ctx.Value(QueryKey)
	if o == nil {
		return nil
	}
	values, ok := o.(url.Values)
	if !ok {
		return nil
	}
	return values
}
