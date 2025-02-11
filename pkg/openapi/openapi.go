package openapi

import (
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"reflect"
)

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
