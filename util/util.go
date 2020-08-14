package util

import (
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// MediaType describe the content type of an HTTP request or HTTP response.
type MediaType struct {
	// Type is the HTTP content type represents. such as
	// "text/html", "image/jpeg".
	Type string
	// Charset is the HTTP content encoding represents.
	Charset string
}

// ContentType returns the HTTP header content-type value.
func (m MediaType) ContentType() string {
	if len(m.Type) > 0 && m.Charset != "" {
		return fmt.Sprintf("%s; charset=%s", m.Type, m.Charset)
	}
	return m.Type
}

// ParseMediaType parsing a specified string v to MediaType struct.
func ParseMediaType(v string) MediaType {
	if v == "" {
		return MediaType{}
	}

	mimetype, params, err := mime.ParseMediaType(v)
	if err != nil {
		return MediaType{}
	}
	return MediaType{
		Type:    mimetype,
		Charset: params["charset"],
	}
}

func clone(response *http.Response) *http.Response {
	copyed := &http.Response{}
	*copyed = *response
	copyed.Header = http.Header{}
	for key, value := range response.Header {
		copyed.Header[key] = value
	}

	copyed.Trailer = http.Header{}
	for key, value := range response.Trailer {
		copyed.Trailer[key] = value
	}
	return copyed
}

func WrapUncompress(response *http.Response, nocopy ...bool) (*http.Response, error) {
	switch response.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err := gzip.NewReader(response.Body)
		if err != nil {
			return nil, err
		}
		if len(nocopy) > 0 && nocopy[0] {
			response.Body = reader
			return response, nil
		}

		copyed := clone(response)
		copyed.Header.Del("Content-Encoding")
		copyed.Body = reader
		return copyed, nil
	default:
		return response, nil
	}
}

func WrapCharset(response *http.Response, nocopy ...bool) (*http.Response, error) {
	mediatype := ParseMediaType(response.Header.Get("Content-Type"))
	if mediatype.Charset == "" {
		return response, nil
	}

	ce, err := htmlindex.Get(mediatype.Charset)
	if err != nil {
		return nil, err
	}

	reader := transform.NewReader(response.Body, ce.NewDecoder())
	if len(nocopy) > 0 && nocopy[0] {
		response.Body = readcloser{Reader: reader, Closer: response.Body}
		return response, nil
	}

	copyed := clone(response)
	copyed.Header.Set("Content-Type", mediatype.Type)
	copyed.Body = readcloser{Reader: reader, Closer: response.Body}
	return copyed, nil
}

type readcloser struct {
	io.Reader
	io.Closer
}
