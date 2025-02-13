package arrays

import (
	"github.com/getkin/kin-openapi/openapi3"
)

func MergeParameters(src openapi3.Parameters, dest openapi3.Parameters) (parameters openapi3.Parameters) {
	result := make(map[string]*openapi3.ParameterRef)
	for _, srcParameter := range src {
		result[srcParameter.Value.Name+srcParameter.Value.In] = srcParameter
	}

	for _, destParameter := range dest {
		key := destParameter.Value.Name + destParameter.Value.In

		// There was a request without this parameter
		// So, we now assume it was not required
		if _, ok := result[key]; !ok {
			destParameter.Value.Required = false
		} else {
			// We could merge parameters here
			// Such as to add example values
		}

		result[key] = destParameter
	}

	for _, parameter := range result {
		parameters = append(parameters, parameter)
	}
	return
}
