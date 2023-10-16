package resty

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/runner-mei/errors"
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

func GetTokenStringFunc(prx *Proxy, loginURL, username, password string) func(context.Context, bool) (string, error) {
	if prx == nil {
		prx = Default
	}

	var cachedToken string
	var cachedExpiresAt time.Time

	return func(ctx context.Context, force bool) (string, error) {
		if !force && cachedToken != "" && time.Now().Before(cachedExpiresAt) {
			return cachedToken, nil
		}

		var auth struct {
			Token     string `json:"token"`
			ExpiresIn int64  `json:"expires_in"`
		}

		err := prx.New(loginURL).
			SetParam("_method", "POST").
			SetParam("username", username).
			SetParam("password", password).
			Result(&auth).
			GET(ctx)
		if err != nil {
			if err.HTTPCode() == http.StatusNotFound {
				return "", errors.NewError(http.StatusUnauthorized, "read token fail")
			}
			var ue *url.Error
			if errors.As(err, &ue) {
				if ue.Err != nil {
					return "", errors.RuntimeWrap(ue.Err, "read token fail")
				}
			}
			return "", errors.RuntimeWrap(err, "read token fail")
		}
		if auth.Token == "" {
			return "", errors.NewError(http.StatusInternalServerError,
				"get token fail, token is empty string")
		}
		cachedToken = auth.Token
		cachedExpiresAt = time.Now().Add(time.Duration(auth.ExpiresIn-5) * time.Second)
		return cachedToken, nil
	}
}

func GetTokenFunc(prx *Proxy, loginURL, username, password string) func(context.Context, *Request, bool) (*Request, error) {
	readToken := GetTokenStringFunc(prx, loginURL, username, password)

	return func(ctx context.Context, r *Request, force bool) (*Request, error) {
		token, err := readToken(ctx, force)
		if err != nil {
			return nil, err
		}
		return r.SetParam("token", token), nil
	}
}
