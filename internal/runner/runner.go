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
	"os"
	"path"
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
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			var result output.Result
			err := json.Unmarshal([]byte(line), &result)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("could not unmarshal input file: %s", options.InputFile)
			}

			err = processResult(&result)
			if err != nil {
				return err
			}
		}
	} else {
		return errorutil.NewWithErr(fmt.Errorf("invalid input file format: %s", options.InputFile))
	}

	for filename, spec := range allSpecs {
		targetFile := path.Join(options.StoreOpenAPIDir, filename)
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

	allSpecs[filename].AddOperation(parsedURL.Path, result.Request.Method, &openapi3.Operation{
		Parameters: requestParameters,
		Responses:  openapi3.NewResponses(),
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
