package runner

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/oneaudit/katana-ng/pkg/output"
	"github.com/oneaudit/oppa/pkg/api"
	"github.com/oneaudit/oppa/pkg/openapi"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/oneaudit/oppa/pkg/utils/arrays"
	urlhelper "github.com/oneaudit/oppa/pkg/utils/urls"
	"github.com/projectdiscovery/gologger"
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

	if err := api.ValidateOptions(options); err != nil {
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
			if line == "\n" {
				break
			}

			var result output.Result
			err = json.Unmarshal([]byte(line), &result)
			if err != nil {
				gologger.Warning().Msgf("could not unmarshal input file: %s", options.InputFile)
				continue
			}

			err = processResult(options, &result)
			if err != nil {
				gologger.Warning().Msgf("could not process result: %s", result.Request.URL)
				continue
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
			responseStatusCode, _ := strconv.Atoi(row[13])

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

			decodedBytes, err = base64.StdEncoding.DecodeString(row[23])
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not decode response: %s", row[0])
			}
			result.Response.Raw = string(decodedBytes)

			// If we have to, we parse the response and extract the status code
			if result.Response.StatusCode == 0 {
				parsedRawHttp, err = urlhelper.ParseRawHTTP(result.Response.Raw, false)
				if err != nil {
					gologger.Warning().Msgf("could not parse response: %s", result.Response.Raw)
					continue
				}
				result.Response.StatusCode = parsedRawHttp.StatusCode
			}

			err = processResult(options, &result)
			if err != nil {
				gologger.Warning().Msgf("could not process result: %s (%v)", result.Request.URL, err.Error())
				continue
			}
		}
	} else {
		return errorutil.NewWithErr(fmt.Errorf("invalid input file format: %s", options.InputFileMode))
	}

	for filename, spec := range allSpecs {
		targetFile := path.Join(options.OutputDirectory, filename)
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
	var StatusCode int
	if result.Response != nil {
		StatusCode = result.Response.StatusCode
	} else {
		// if there is no response
		// by design, we ignore these
		gologger.Debug().Msgf("[SKIPPED] No response code for %s", URL)
		return nil
	}

	// We are only skipping 404 files for GET requests
	// (and this noise reducing option can be disabled)
	if !options.Keep404 && StatusCode == 404 && result.Request.Method == "GET" {
		cleanedURL := strings.Split(URL, "?")[0]
		if !strings.HasSuffix(cleanedURL, "/") {
			gologger.Debug().Msgf("[FILTERED] Filtered 404 URL: %s", URL)
			return nil
		}
	}

	parsedURL, err := urlutil.Parse(URL)
	if err != nil {
		return err
	}

	// matching endpoints are ignored
	for _, regex := range options.FilterEndpointsRegex {
		if regex.MatchString(parsedURL.Path) {
			// .ico endpoints are always welcomed (sorry not sorry)
			if !strings.HasSuffix(parsedURL.Path, ".ico") {
				gologger.Debug().Msgf("[FILTERED] Filtered URL by Regex: %s", URL)
				return nil
			}
		}
	}

	gologger.Info().Msgf("Processing URL [%d]: %s", StatusCode, URL)

	domain := parsedURL.Host

	// Multiple websites can be hosted on one domain
	for _, root := range options.ServerRoots {
		if strings.HasPrefix(parsedURL.Path, root) {
			extraRoot := strings.TrimSuffix(root, "/")
			domain += extraRoot
			parsedURL.Path = strings.Replace(parsedURL.Path, extraRoot, "", 1)
		}
	}

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
	origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	if !options.NoOrigin {
		if _, found := result.Request.Headers["Origin"]; !found {
			result.Request.Headers["Origin"] = origin
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

	var requestBody *openapi3.RequestBodyRef
	hasRequestBody := false

	// Correct method to fix some edge cases
	result.Request.Method = strings.ReplaceAll(strings.ReplaceAll(result.Request.Method, "\\", ""), "\"", "")

	switch result.Request.Method {
	case http.MethodDelete:
		hasRequestBody = true
	case http.MethodPatch:
		hasRequestBody = true
	case http.MethodPost:
		hasRequestBody = true
	case http.MethodPut:
		hasRequestBody = true
	case http.MethodTrace:
		hasRequestBody = true
	}
	if hasRequestBody {
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
			requestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithContent(
				openapi3.NewContentWithSchema(schema, []string{contentType}),
			)}
		}
	}

	responses := openapi3.NewResponses()
	extensions := make(map[string]any)
	if result.Response != nil {
		if StatusCode != 0 {
			responses.Set(
				strconv.Itoa(StatusCode),
				&openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("No description")},
			)
		}

		if result.Response.Raw != "" {
			parsedResponse, err := urlhelper.ParseRawHTTP(result.Response.Raw, false)
			if err != nil {
				return errorutil.NewWithErr(err)
			}
			// set status code
			responses.Set(
				strconv.Itoa(parsedResponse.StatusCode),
				&openapi3.ResponseRef{Value: openapi3.NewResponse().WithDescription("No description")},
			)
			// set extensions
			if parsedResponse.Headers != nil && strings.HasPrefix(parsedResponse.Headers["Content-Type"], "text/html") {
				reader, err := goquery.NewDocumentFromReader(strings.NewReader(parsedResponse.Body))
				if err != nil {
					return errorutil.NewWithErr(err)
				}
				var scriptSrcendpoints []string
				reader.Find("script[src]").Each(func(i int, item *goquery.Selection) {
					src, ok := item.Attr("src")
					if ok && src != "" && strings.HasPrefix(src, "http") && !strings.HasPrefix(src, origin) {
						scriptSrcendpoints = append(scriptSrcendpoints, src)
					}
				})
				extensions["x-javascript-libs"] = scriptSrcendpoints
			}
		}
	}

	// Correct path to fix some edge cases
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	}

	if allSpecs[filename].Paths == nil {
		allSpecs[filename].Paths = openapi3.NewPaths()
	}

	src := &openapi3.Operation{
		Parameters:  requestParameters,
		RequestBody: requestBody,
		Responses:   responses,
	}

	handleMergeLogic(options, allSpecs[filename].Paths, result.Request.Method, parsedURL.Path, extensions, origin, src)

	return nil
}

func handleMergeLogic(options *types.Options, paths *openapi3.Paths, method string, path string, extensions map[string]any, origin string, src *openapi3.Operation) bool {
	pathItem := paths.Value(path)
	if pathItem == nil {
		pathItem = &openapi3.PathItem{}
		paths.Set(path, pathItem)

		// There is no problem as there is no operation
		addOperationToItem(src, extractOperation(pathItem, method))
		mergeExtensions(pathItem, extensions)
		return true
	}

	operation := extractOperation(pathItem, method)
	if *operation == nil {
		// We are the first to use this method on this path
		// Hence, there is no merge logic and again no problem
		addOperationToItem(src, operation)
		mergeExtensions(pathItem, extensions)
		return true
	}

	// The default logic would be to create a new entry for each path
	// Like imagine, we got "/?p=1" and "/?p=2", this would result in
	// - "/" for "/?p=1"
	// - "//" for "/?p=2"
	// Ensuring that we kept as much information as possible
	//
	// But, this may result as many duplicate routes for some websites
	// So, we are adding a deduplicate logic, to exclude some
	dest := *operation
	duplicate := true
	skipped := 0
	for _, srcParameter := range src.Parameters {
		srcKeyRaw, _ := json.Marshal(srcParameter.Value)
		srcKey := string(srcKeyRaw)
		foundKey := false

		for _, destParameter := range dest.Parameters {
			destKeyRaw, _ := json.Marshal(destParameter.Value)
			destKey := string(destKeyRaw)

			if destKey == srcKey {
				foundKey = true
				break
			}
		}

		// Apache and Jetty Directory Listing
		if srcParameter.Value.Name == "C" || srcParameter.Value.Name == "O" {
			strValue, ok := srcParameter.Value.Schema.Value.Default.(string)
			if ok {
				for _, uselessParameter := range []string{"D;O=A", "D;O=D", "S;O=A", "S;O=D", "M;O=A", "M;O=D", "N;O=A", "N;O=D", "A", "M", "N", "S"} {
					if uselessParameter == strValue {
						if !foundKey {
							skipped++
						}
						foundKey = true
						break
					}
				}
			}
		} else
		// Origin Header
		if srcParameter.Value.Name == "Origin" {
			strValue, ok := srcParameter.Value.Schema.Value.Default.(string)
			if ok && strValue == origin {
				if !foundKey {
					skipped++
				}
				foundKey = true
			}
		} else
		// This parameter seems to be a timestamp, we don't generate a new entry per timestamp
		if srcParameter.Value.Name == "timestamp" {
			strValue, ok := srcParameter.Value.Schema.Value.Default.(string)
			if ok && len(strValue) == 10 {
				// we don't increase skipped
				// as we want at least one value
				foundKey = true
			}
		}

		if !foundKey {
			duplicate = false
		}
	}

	// If there is no new attribute
	if duplicate && (len(dest.Parameters)+skipped) == len(src.Parameters) {
		return false
	}

	return handleMergeLogic(options, paths, method, "/"+path, nil, "", src)
}

func mergeExtensions(pathItem *openapi3.PathItem, extensions map[string]any) {
	pathItem.Extensions = arrays.MergeExtensions(extensions, pathItem.Extensions)
}

func addOperationToItem(src *openapi3.Operation, dest **openapi3.Operation) {
	// Remove the default response (if there is one other status code)
	src.Responses = arrays.MergeResponses(src.Responses, src.Responses)
	// No merge logic, dest is assumed to be empty
	*dest = src
}

func extractOperation(pathItem *openapi3.PathItem, method string) **openapi3.Operation {
	switch method {
	case http.MethodConnect:
		return &pathItem.Connect
	case http.MethodDelete:
		return &pathItem.Delete
	case http.MethodGet:
		return &pathItem.Get
	case http.MethodHead:
		return &pathItem.Head
	case http.MethodOptions:
		return &pathItem.Options
	case http.MethodPatch:
		return &pathItem.Patch
	case http.MethodPost:
		return &pathItem.Post
	case http.MethodPut:
		return &pathItem.Put
	case http.MethodTrace:
		return &pathItem.Trace
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
		case '?':
			builder.WriteRune('_')
		case '/':
			builder.WriteRune('_')
		default:
			builder.WriteRune(char)
		}
	}
	return builder.String()
}
