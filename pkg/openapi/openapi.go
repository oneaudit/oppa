package openapi

import (
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
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
