package api

import (
	"fmt"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/projectdiscovery/goflags"
)

func MakeFlagSet(options *types.Options, cfgFile *string) *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Oppa is a toolkit to generate OpenAPI specifications from JSON lines.`)

	flagSet.CreateGroup("input", "Target",
		flagSet.StringVarP(&options.InputFile, "target", "t", "", "target input file to parse"),
		flagSet.StringVarP(&options.InputFileMode, "input-mode", "im", "jsonl", fmt.Sprintf("mode of input file (%v)", []string{"jsonl", "logger++"})),
		flagSet.StringSliceVarP(&options.ServerRoots, "server-root", "sr", nil, "Manually define server roots.", goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(cfgFile, "config", "", "path to the oppa configuration file"),
	)

	flagSet.CreateGroup("tuning", "Tuning",
		flagSet.BoolVarP(&options.NoOrigin, "n", "no-origin", false, "By default, oppa adds an Origin header to all paths."),
		flagSet.BoolVarP(&options.Keep404, "k4", "keep-404", false, "By default, oppa skips file endpoint with a 404 code."),
		flagSet.StringSliceVarP(&options.FilterEndpoints, "fr", "filter-regex", nil, "Skip endpoints based on a regex.", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.FilterEndpointsBase, "frb", "filter-regex-base", nil, "Skip endpoints based on a regex.", goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputDirectory, "output-dir", "d", "", "store openapi to custom directory"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display output only"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVar(&options.Debug, "debug", false, "display debug output"),
		flagSet.BoolVar(&options.Version, "version", false, "display project version"),
	)
	return flagSet
}
