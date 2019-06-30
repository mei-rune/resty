package resty

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type TestData struct {
	exceptedMethod  string
	exceptedHeaders url.Values
	exceptedURL     string
	exceptedBody    string
	responseCode    int
	responseBody    string
}

func echoFunc(t *testing.T, data *TestData) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data.exceptedMethod != "" {
			if data.exceptedMethod != r.Method {
				t.Error("method excepted:", data.exceptedMethod)
				t.Error("method actual  :", r.Method)
			}
		}

		if len(data.exceptedHeaders) > 0 {
			for key, values := range data.exceptedHeaders {
				actual := r.Header[key]
				if !reflect.DeepEqual(actual, values) {
					t.Error("header excepted:", key, values)
					t.Error("header actual  :", key, actual)
				}
			}
		}

		if data.exceptedURL != "" {
			if actual := r.URL.String(); actual != data.exceptedURL {
				t.Error("url excepted:", data.exceptedURL)
				t.Error("url actual  :", actual)
			}
		}

		if data.exceptedBody != "" {
			bs, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			if s := string(bs); data.exceptedBody != s {
				t.Error("body excepted:", data.exceptedBody)
				t.Error("body actual  :", s)
			}
		}

		if data.responseCode == 0 {
			data.responseCode = http.StatusOK
		}
		if len(data.responseBody) == 0 {
			data.responseBody = "OK"
		}

		w.WriteHeader(data.responseCode)
		w.Write([]byte(data.responseBody))
	})
}

func assetBody(t *testing.T, req *Request, code int, excepted string) *Request {
	return req.ExceptedCode(code).
		Result(ResponseFunc(func(ctx context.Context, r *http.Request, res *http.Response) HTTPError {
			bs, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Error(err)
				return nil
			}
			if s := string(bs); s != excepted {
				t.Errorf("response excepted: %s", excepted)
				t.Errorf("response actual  : %s", s)
			}
			return nil
		}))
}

func TestGetFail(t *testing.T) {
	failMessage := "FAIL message"
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "",
		responseCode:    http.StatusInternalServerError,
		responseBody:    failMessage,
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		GET(nil)
	if err == nil {
		t.Error("err is nil")
		return
	}

	if !strings.Contains(err.Error(), failMessage) {
		t.Errorf("response excepted: %s", failMessage)
		t.Errorf("response actual  : %s", err)
	}
}

func TestGetOK(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestPutOK(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "PUT",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "test",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		SetBody("test").
		PUT(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestPostOK(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "POST",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "test",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		SetBody("test").
		POST(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestDeleteOK(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "DELETE",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "test",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		SetBody("test").
		DELETE(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestSetHeader(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		AddHeader("Yaaa", "1").
		AddHeader("Yaaa", "1").
		SetHeader("Yaaa", "abc").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestAddHeader(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc", "1", "1"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		AddHeader("Yaaa", "1").
		AddHeader("Yaaa", "1").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestSetParam(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod: "GET",
		exceptedURL:    "/test1/a?Yaaa=abc",
		exceptedBody:   "",
		responseCode:   http.StatusOK,
		responseBody:   "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		AddParam("Yaaa", "1").
		AddParam("Yaaa", "1").
		SetParam("Yaaa", "abc").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestAddParam(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod: "GET",
		exceptedURL:    "/test1/a?Yaaa=abc&Yaaa=1&Yaaa=1",
		exceptedBody:   "",
		responseCode:   http.StatusOK,
		responseBody:   "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetParam("Yaaa", "abc").
		AddParam("Yaaa", "1").
		AddParam("Yaaa", "1").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestBytesBody(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "POST",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    "test",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		SetBody([]byte("test")).
		POST(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestJsonBody(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "POST",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		exceptedBody:    `{"a":"b"}` + "\n",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		SetBody(map[string]interface{}{"a": "b"}).
		POST(nil)
	if err != nil {
		t.Error(err)
	}
}

func TestGetBytes(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	var body []byte
	err := prx.New("/a").
		Result(&body).
		SetHeader("Yaaa", "abc").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
	if string(body) != "OK" {
		t.Errorf("body %s", body)
	}
}

func TestGetString(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		responseCode:    http.StatusOK,
		responseBody:    "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	var body string
	err := prx.New("/a").
		Result(&body).
		SetHeader("Yaaa", "abc").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
	if body != "OK" {
		t.Errorf("body %s", body)
	}
}

func TestGetJson(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		responseCode:    http.StatusOK,
		responseBody:    "{\"a\":\"b\"}",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	var body map[string]string
	err := prx.New("/a").
		Result(&body).
		SetHeader("Yaaa", "abc").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
	if body["a"] != "b" {
		t.Errorf("body %s", body)
	}
}

func TestGetWriter(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod:  "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"}},
		exceptedURL:     "/test1/a",
		responseCode:    http.StatusOK,
		responseBody:    "ok",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1")
	prx, _ := New(urlStr)

	var body bytes.Buffer
	err := prx.New("/a").
		Result(&body).
		SetHeader("Yaaa", "abc").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
	if body.String() != "ok" {
		t.Errorf("body %s", body.String())
	}
}

func TestProxyData(t *testing.T) {
	hsrv := httptest.NewServer(echoFunc(t, &TestData{
		exceptedMethod: "GET",
		exceptedHeaders: url.Values{"Yaaa": []string{"abc"},
			"Ybbb": []string{"abb"}},
		exceptedURL:  "/test1/a?a=b&c=d",
		exceptedBody: "",
		responseCode: http.StatusOK,
		responseBody: "OK",
	}))
	defer hsrv.Close()

	urlStr := Join(hsrv.URL, "/test1?c=d")
	prx, _ := New(urlStr)
	prx.SetHeader("Ybbb", "abb")

	err := assetBody(t, prx.New("/a"), 0, "OK").
		SetHeader("Yaaa", "abc").
		SetParam("a", "b").
		GET(nil)
	if err != nil {
		t.Error(err)
	}
}
