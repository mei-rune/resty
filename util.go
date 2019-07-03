package resty

import (
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
