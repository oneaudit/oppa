package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/output"
	errorutil "github.com/projectdiscovery/utils/errors"
	"os"
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

			processResult(&result, options)
		}
	} else {
		return errorutil.NewWithErr(fmt.Errorf("invalid input file format: %s", options.InputFile))
	}

	return nil
}

func processResult(result *output.Result, options *types.Options) {
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
