package api

import (
	"github.com/oneaudit/oppa/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	"os"
	"regexp"
)

const DefaultOpenAPIDir = "oppa_openapi"

func CreateDefaultOptionsFromFile(cfgFile string) (*types.Options, error) {
	cfgOptions := &types.Options{}
	flagSet := MakeFlagSet(cfgOptions, &cfgFile)
	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not read config file")
		}
	}
	return cfgOptions, nil
}

func ValidateOptions(options *types.Options) error {
	if options.OutputDirectory == "" {
		options.OutputDirectory = DefaultOpenAPIDir
	}
	if !options.CLI {
		_ = os.MkdirAll(options.OutputDirectory, os.ModePerm)
	}

	for _, fr := range options.FilterEndpoints {
		cr, err := regexp.Compile(fr)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("Invalid regex for filter endpoint option")
		}
		options.FilterEndpointsRegex = append(options.FilterEndpointsRegex, cr)
	}
	for _, fr := range options.FilterEndpointsBase {
		cr, err := regexp.Compile(fr)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("Invalid regex for filter endpoint option")
		}
		options.FilterEndpointsRegex = append(options.FilterEndpointsRegex, cr)
	}
	return nil
}
