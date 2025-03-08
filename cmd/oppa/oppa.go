package main

import (
	"fmt"
	"github.com/oneaudit/oppa/internal/runner"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	cfgFile string
	options = &types.Options{}
)

func main() {
	_, err := readFlags()
	if err != nil {
		gologger.Fatal().Msgf("Could not read flags: %s\n", err)
	}
	err = runner.Execute(options)
	if err != nil {
		if options.Version {
			return
		}
		gologger.Fatal().Msgf("could not create runner: %s\n", err)
	}
}

func readFlags() (*goflags.FlagSet, error) {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Oppa is a toolkit to generate OpenAPI specifications from JSON lines.`)

	flagSet.CreateGroup("input", "Target",
		flagSet.StringVarP(&options.InputFile, "target", "t", "", "target input file to parse"),
		flagSet.StringVarP(&options.InputFileMode, "input-mode", "im", "jsonl", fmt.Sprintf("mode of input file (%v)", []string{"jsonl", "logger++"})),
		flagSet.StringSliceVarP(&options.ServerRoots, "server-root", "sr", goflags.StringSlice{}, "Manually define server roots.", goflags.Options{}),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&cfgFile, "config", "", "path to the oppa configuration file"),
	)

	flagSet.CreateGroup("tuning", "Tuning",
		flagSet.BoolVarP(&options.NoOrigin, "n", "no-origin", false, "By default, oppa adds an Origin header to all paths."),
		flagSet.BoolVarP(&options.Keep404, "k4", "keep-404", false, "By default, oppa skips file endpoint with a 404 code."),
		flagSet.StringSliceVarP(&options.FilterEndpoints, "fr", "filter-regex", goflags.StringSlice{}, "Skip endpoints based on a regex.", goflags.Options{}),
		flagSet.StringSliceVarP(&options.FilterEndpointsBase, "frb", "filter-regex-base", goflags.StringSlice{}, "Skip endpoints based on a regex.", goflags.Options{}),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputDirectory, "output-dir", "d", "", "store openapi to custom directory"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display output only"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVar(&options.Debug, "debug", false, "display debug output"),
		flagSet.BoolVar(&options.Version, "version", false, "display project version"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not parse flags")
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not read config file")
		}
	}

	return flagSet, nil
}
