package main

import (
	"github.com/oneaudit/oppa/internal/runner"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var options = &types.Options{}

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

	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVar(&options.Silent, "silent", false, "display output only"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVar(&options.Debug, "debug", false, "display debug output"),
		flagSet.BoolVar(&options.Version, "version", false, "display project version"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not parse flags")
	}

	return flagSet, nil
}
