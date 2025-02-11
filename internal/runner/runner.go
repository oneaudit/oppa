package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oneaudit/oppa/pkg/openapi"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/output"
	errorutil "github.com/projectdiscovery/utils/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
)

const DefaultOpenAPIDir = "oppa_openapi"

var allSpecs = make(map[string]*openapi3.T)

func Execute(options *types.Options) error {
	options.ConfigureOutput()
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current version: %s", version)
		return nil
	}

	var storeOpenAPIDir = DefaultOpenAPIDir
	if options.StoreOpenAPIDir != DefaultOpenAPIDir && options.StoreOpenAPIDir != "" {
		storeOpenAPIDir = options.StoreOpenAPIDir
	}
	_ = os.MkdirAll(storeOpenAPIDir, os.ModePerm)

	if err := validateOptions(options); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not validate options")
	}

	// Open File
	file, err := os.Open(options.InputFile)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not open input file: %s", options.InputFile)
	}
	defer file.Close()

	// Parse File
	if options.InputFileMode == "jsonl" {
		reader := bufio.NewReader(file)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				return errorutil.NewWithErr(err).Msgf("could not read input file")
			}

			var result output.Result
			err = json.Unmarshal([]byte(line), &result)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not unmarshal input file: %s", options.InputFile)
			}

			err = processResult(&result)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not process result: %s", options.InputFile)
			}
		}
	} else {
		return errorutil.NewWithErr(fmt.Errorf("invalid input file format: %s", options.InputFile))
	}

	for filename, spec := range allSpecs {
		targetFile := path.Join(options.StoreOpenAPIDir, filename)
		gologger.Info().Msgf("Creating OpenAPI specification: %s", targetFile)
		file, err := os.Create(targetFile)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not create output file: %s", targetFile)
		}
		defer file.Close()

		encoder := yaml.NewEncoder(file)
		encoder.SetIndent(2)
		err = encoder.Encode(&spec)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not write output file: %s", targetFile)
		}
	}

	return nil
}

func processResult(result *output.Result) error {
	URL := result.Request.URL
	gologger.Info().Msgf("Processing URL: %s", URL)

	parsedURL, err := urlutil.Parse(URL)
	if err != nil {
		return err
	}
	domain := parsedURL.Host
	filename := cleanDomainName(domain) + ".yaml"

	if _, exists := allSpecs[filename]; !exists {
		allSpecs[filename] = openapi.New(domain, parsedURL.Scheme)
	}

	// Handle query parameters
	requestParameters := openapi3.Parameters{}
	queryParams := parsedURL.Params
	queryParams.Iterate(func(key string, value []string) bool {
		var schema *openapi3.Schema
		if len(value) == 0 {
			schema = openapi3.NewStringSchema()
		} else {
			if len(value) > 1 {
				gologger.Warning().Msgf("Multiple values found for key: %s", key)
				return true
			} else {
				schema = openapi3.NewStringSchema().WithDefault(value[0])
			}
		}
		requestParameters = append(requestParameters,
			&openapi3.ParameterRef{Value: openapi3.NewQueryParameter(key).WithSchema(schema)})
		return true
	})

	var responseBody *openapi3.RequestBodyRef
	hasResponseBody := false
	switch result.Request.Method {
	case http.MethodDelete:
		hasResponseBody = true
	case http.MethodPatch:
		hasResponseBody = true
	case http.MethodPost:
		hasResponseBody = true
	case http.MethodPut:
		hasResponseBody = true
	case http.MethodTrace:
		hasResponseBody = true
	}
	if hasResponseBody {
		contentType := result.Request.Headers["Content-Type"]
		schema := openapi3.NewObjectSchema()
		switch {
		case strings.Contains(contentType, "application/json"):
			var bodyParams map[string]interface{}
			err = json.Unmarshal([]byte(result.Request.Body), &bodyParams)
			if err != nil {
				return err
			}
			for key, value := range bodyParams {
				keySchema := openapi3.NewSchema()
				keySchema.Type = &openapi3.Types{openapi.IdentifySchemaType(value)}
				keySchema.Default = value
				schema = schema.WithProperty(key, keySchema)
			}
		case strings.Contains(contentType, "application/x-www-form-urlencoded"):
			bodyParams, err := url.ParseQuery(result.Request.Body)
			if err != nil {
				return err
			}
			for key, values := range bodyParams {
				var value any
				if len(values) == 0 {
					value = ""
				} else {
					if len(values) == 1 {
						value = values[0]
					} else {
						value = values
					}
				}

				keySchema := openapi3.NewSchema()
				keySchema.Type = &openapi3.Types{openapi.IdentifySchemaType(value)}
				keySchema.Default = value
				schema = schema.WithProperty(key, keySchema)
			}
		default:
			return errorutil.NewWithErr(err)
		}

		if schema.Properties != nil {
			responseBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithContent(
				openapi3.NewContentWithSchema(schema, []string{contentType}),
			)}
		}
	}

	responses := &openapi3.Responses{}
	if result.Response != nil && result.Response.StatusCode != 0 {
		responses.Set(
			strconv.Itoa(result.Response.StatusCode),
			&openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("No description")},
		)
	} else {
		responses = openapi3.NewResponses()
	}

	allSpecs[filename].AddOperation(parsedURL.Path, result.Request.Method, &openapi3.Operation{
		Parameters:  requestParameters,
		RequestBody: responseBody,
		Responses:   responses,
	})

	return nil
}

func cleanDomainName(domain string) string {
	// It may not be secure as URLParse
	// is the only layer of security we use
	var builder strings.Builder
	for _, char := range domain {
		switch char {
		case '.':
			builder.WriteRune('_')
		case ':':
			builder.WriteRune('_')
		case '/':
			builder.WriteRune('_')
		default:
			builder.WriteRune(char)
		}
	}
	return builder.String()
}
