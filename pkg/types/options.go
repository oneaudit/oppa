package types

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	logutil "github.com/projectdiscovery/utils/log"
	"regexp"
)

type Options struct {
	// InputFileMode input file
	InputFile string
	// InputFileMode specifies the mode of input file (jsonl, etc)
	InputFileMode string
	// NoOrigin defines if we are adding Origin: to all requests
	NoOrigin bool
	// OutputDirectory specifies custom directory to store openapi specifications
	OutputDirectory string
	// Keep404 keep response codes equals to 404 for files
	Keep404 bool
	// FilterEndpoints filter endpoints using regexes
	FilterEndpoints goflags.StringSlice
	// FilterEndpointsBase filter endpoints using regexes (intended usage for generic configuration files)
	FilterEndpointsBase goflags.StringSlice
	// FilterEndpointsRegex filter endpoints using regexes
	FilterEndpointsRegex []*regexp.Regexp
	// Silent shows only output
	Silent bool
	// Verbose specifies showing verbose output
	Verbose bool
	// Debug
	Debug bool
	// Version enables showing of tool version
	Version bool
}

// ConfigureOutput configures the output logging levels to be displayed on the screen
func (options *Options) ConfigureOutput() {
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	} else if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	logutil.DisableDefaultLogger()
}
