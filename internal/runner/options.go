package runner

import (
	"github.com/oneaudit/oppa/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	"regexp"
)

func validateOptions(options *types.Options) error {
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
