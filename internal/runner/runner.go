package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/oneaudit/oppa/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/output"
	errorutil "github.com/projectdiscovery/utils/errors"
	"log"
	"os"
)

func Execute(options *types.Options) error {
	options.ConfigureOutput()
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current version: %s", version)
		return nil
	}

	if err := validateOptions(options); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not validate options")
	}

	// Open the file
	file, err := os.Open(".data/output.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		var result output.Result
		err := json.Unmarshal([]byte(line), &result)
		if err != nil {
			log.Printf("Error unmarshaling line: %s\n", err)
			continue
		}

		// Process the result (just printing here for demo)
		fmt.Printf("Processed Result: %+v\n", result.Request.URL)
	}

	return scanner.Err()
}
