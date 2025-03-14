package openapi

import (
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"reflect"
)

// We are allowing "origin" while we hope the value is appropriate (not a fuzzed one)
var httpUninterestingHeaders = []string{
	// Known request headers
	// Excluded: "content-type", "origin",
	"a-im", "accept", "accept-charset", "accept-datetime", "accept-encoding", "accept-language", "access-control-request-method",
	"cache-control", "connection", "content-encoding", "content-length", "content-md5", "date", "expect",
	"forwarded", "from", "host", "http2-settings", "if-match", "if-modified-since", "if-none-match", "if-range", "if-unmodified-since",
	"max-forwards", "pragma", "prefer", "range", "referer", "te", "trailer", "transfer-encoding", "user-agent", "upgrade",
	"via", "warning", "upgrade-insecure-requests", "x-requested-with", "dnt", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
	"front-end-https", "x-att-deviceid", "x-wap-profile", "proxy-connection", "x-uidh", "x-csrf-token", "x-request-id", "x-correlation-id",
	"save-data", "priority",
	// CORS
	"access-control-request-method", "access-control-request-headers",
	// Browser Headers
	"sec-gpc", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-key", "sec-fetch-site", "sec-fetch-user",
	"sec-fetch-mode", "sec-fetch-dest", "sec-fetch-storage-access", "sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile",
	// Interesting
	"cookie", "authorization", "proxy-authorization", "x-http-method-override",
}

func IsUninterestingHeader(header string) bool {
	// quick check
	if header == "content-type" || header == "origin" {
		return false
	}

	for _, h := range httpUninterestingHeaders {
		if h == header {
			return true
		}
	}

	return false
}

func New(baseEndpoint string, scheme string) *openapi3.T {
	return &openapi3.T{
		OpenAPI: "3.0.0",
		Info: &openapi3.Info{
			Title:       baseEndpoint,
			Version:     "1.0.0",
			Description: fmt.Sprintf("Crawled %s", baseEndpoint),
		},
		Paths: &openapi3.Paths{},
		Servers: openapi3.Servers{
			&openapi3.Server{
				URL: fmt.Sprintf("%s://%s", scheme, baseEndpoint),
			},
		},
	}
}

func IdentifySchemaType(value any) string {
	v := reflect.ValueOf(value)

	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		return openapi3.TypeArray
	case reflect.Bool:
		return openapi3.TypeBoolean
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return openapi3.TypeInteger
	case reflect.Float32, reflect.Float64:
		return openapi3.TypeNumber
	case reflect.Map:
		return openapi3.TypeObject
	case reflect.String:
		return openapi3.TypeString
	case reflect.Ptr:
		if v.IsNil() {
			return openapi3.TypeNull
		}
		return IdentifySchemaType(v.Elem().Interface())
	default:
		return openapi3.TypeNull
	}
}
