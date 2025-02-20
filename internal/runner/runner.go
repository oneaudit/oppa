package runner

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oneaudit/oppa/pkg/openapi"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/oneaudit/oppa/pkg/utils/arrays"
	urlhelper "github.com/oneaudit/oppa/pkg/utils/urls"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/navigation"
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
	//goland:noinspection GoUnhandledErrorResult
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
			if line == "\n" {
				break
			}

			var result output.Result
			err = json.Unmarshal([]byte(line), &result)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not unmarshal input file: %s", options.InputFile)
			}

			err = processResult(options, &result)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not process result: %s", result.Request.URL)
			}
		}
	} else if options.InputFileMode == "logger++" {
		reader := csv.NewReader(file)
		rows, err := reader.ReadAll()
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not read input file")
		}

		for _, row := range rows {
			if row[3] == "Method" {
				continue
			}

			requestMethod := row[3]
			requestURL := row[7]
			responseStatusCode, _ := strconv.Atoi(row[12])

			var result output.Result
			result.Request = &navigation.Request{
				Method: requestMethod,
				URL:    requestURL,
			}
			result.Response = &navigation.Response{
				StatusCode: responseStatusCode,
			}

			decodedBytes, err := base64.StdEncoding.DecodeString(row[22])
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not decode request: %s", row[0])
			}
			parsedRawHttp, err := urlhelper.ParseRawHTTP(string(decodedBytes), true)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not parse request: %s", row[0])
			}

			// Add missing fields
			result.Request.Headers = parsedRawHttp.Headers
			result.Request.Body = parsedRawHttp.Body

			err = processResult(options, &result)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not process result: %s", result.Request.URL)
			}
		}
	} else {
		return errorutil.NewWithErr(fmt.Errorf("invalid input file format: %s", options.InputFileMode))
	}

	for filename, spec := range allSpecs {
		targetFile := path.Join(storeOpenAPIDir, filename)
		gologger.Info().Msgf("Creating OpenAPI specification: %s", targetFile)
		file, err := os.Create(targetFile)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not create output file: %s", targetFile)
		}
		//goland:noinspection GoDeferInLoop,GoUnhandledErrorResult
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

func processResult(options *types.Options, result *output.Result) error {
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
		// All parameters are required unless we found a route without them
		// (check that is handled when we add the operation)
		requestParameters = append(requestParameters,
			&openapi3.ParameterRef{Value: openapi3.NewQueryParameter(key).WithRequired(true).WithSchema(schema)})
		return true
	})

	// Handle headers
	if result.Request.Headers == nil {
		result.Request.Headers = map[string]string{}
	}
	if options.NoOrigin {
		if _, found := result.Request.Headers["Origin"]; !found {
			result.Request.Headers["Origin"] = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
	}

	for headerName, headerValue := range result.Request.Headers {
		// not interesting
		if strings.ToLower(headerName) == "content-type" {
			continue
		}
		required := true

		// not required
		if strings.ToLower(headerName) == "origin" {
			required = false
		}

		requestParameters = append(requestParameters,
			&openapi3.ParameterRef{Value: openapi3.NewHeaderParameter(headerName).WithRequired(required).WithSchema(
				openapi3.NewStringSchema().WithDefault(headerValue),
			)})
	}

	var responseBody *openapi3.RequestBodyRef
	hasResponseBody := false

	// Correct method to fix some edge cases
	result.Request.Method = strings.ReplaceAll(strings.ReplaceAll(result.Request.Method, "\\", ""), "\"", "")

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
			if result.Request.Body == "" {
				gologger.Error().Msgf("%s body is missing or empty for %s", result.Request.Method, result.Request.URL)
				result.Request.Body = "{\"missing request body\":\"katana\"}"
			}
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
	extensions := make(map[string]any)
	if result.Response != nil && result.Response.StatusCode != 0 {
		responses.Set(
			strconv.Itoa(result.Response.StatusCode),
			&openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("No description")},
		)
	} else {
		responses = openapi3.NewResponses()
	}

	// Correct path to fix some edge cases
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	}

	if allSpecs[filename].Paths == nil {
		allSpecs[filename].Paths = openapi3.NewPaths()
	}
	pathItem := allSpecs[filename].Paths.Value(parsedURL.Path)
	if pathItem == nil {
		pathItem = &openapi3.PathItem{}
		allSpecs[filename].Paths.Set(parsedURL.Path, pathItem)
	}

	// Add operation
	pathItemSafeAddOperation(pathItem, result.Request.Method, &openapi3.Operation{
		Parameters:  requestParameters,
		RequestBody: responseBody,
		Responses:   responses,
		Extensions:  extensions,
	})

	return nil
}

func operatingSafeAdd(operation **openapi3.Operation, src *openapi3.Operation) {
	if *operation == nil {
		*operation = src
	} else {
		dest := *operation
		// Merge responses
		for k, response := range src.Responses.Map() {
			if k == "default" {
				continue
			}
			status, _ := strconv.Atoi(k)
			dest.AddResponse(status, response.Value)
		}

		dest.Parameters = arrays.MergeParameters(src.Parameters, dest.Parameters)
	}
}
func pathItemSafeAddOperation(pathItem *openapi3.PathItem, method string, operation *openapi3.Operation) {
	switch method {
	case http.MethodConnect:
		operatingSafeAdd(&pathItem.Connect, operation)
	case http.MethodDelete:
		operatingSafeAdd(&pathItem.Delete, operation)
	case http.MethodGet:
		operatingSafeAdd(&pathItem.Get, operation)
	case http.MethodHead:
		operatingSafeAdd(&pathItem.Head, operation)
	case http.MethodOptions:
		operatingSafeAdd(&pathItem.Options, operation)
	case http.MethodPatch:
		operatingSafeAdd(&pathItem.Patch, operation)
	case http.MethodPost:
		operatingSafeAdd(&pathItem.Post, operation)
	case http.MethodPut:
		operatingSafeAdd(&pathItem.Put, operation)
	case http.MethodTrace:
		operatingSafeAdd(&pathItem.Trace, operation)
	default:
		panic(fmt.Errorf("unsupported HTTP method %q", method))
	}
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
