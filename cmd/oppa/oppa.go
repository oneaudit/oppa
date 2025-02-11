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
		flagSet.StringVarP(&options.InputFileMode, "input-mode", "im", "jsonl", fmt.Sprintf("mode of input file (%v)", []string{"jsonl"})),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&cfgFile, "config", "", "path to the katana-ng configuration file"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.StoreOpenAPIDir, "store-openapi-dir", "soad", "", "store per-host openapi to custom directory"),
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
