package runner

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oneaudit/katana-ng/pkg/navigation"
	"github.com/oneaudit/katana-ng/pkg/output"
	"github.com/oneaudit/oppa/pkg/api"
	"github.com/oneaudit/oppa/pkg/parser"
	"github.com/oneaudit/oppa/pkg/types"
	urlhelper "github.com/oneaudit/oppa/pkg/utils/urls"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	"gopkg.in/yaml.v3"
	"os"
	"path"
	"strconv"
)

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

			allSpecs, err = parser.ProcessResult(options, &result, allSpecs)
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

			allSpecs, err = parser.ProcessResult(options, &result, allSpecs)
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
