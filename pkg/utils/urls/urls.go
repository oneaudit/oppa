package urls

import (
	"bufio"
	"bytes"
	"github.com/oneaudit/oppa/pkg/openapi"
	errorutil "github.com/projectdiscovery/utils/errors"
	"io"
	"net/http"
	"strings"
)

type ParseHTTP struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"endpoint,omitempty"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func ParseRawHTTP(raw string, isRequest bool) (*ParseHTTP, error) {
	// The function do not support reading from HTTP/2.
	// We are using a space to reduce the number of issues
	requestReader := bufio.NewReader(strings.NewReader(raw))
	header, _ := requestReader.ReadString('\n')
	header = strings.Replace(header, " HTTP/2", " HTTP/1.1", 1)
	header = strings.Replace(header, "HTTP/2 ", "HTTP/1.1 ", 1)

	var modifiedRequest bytes.Buffer
	modifiedRequest.WriteString(header)
	_, _ = modifiedRequest.ReadFrom(requestReader)

	reader := bufio.NewReader(&modifiedRequest)

	var (
		result     ParseHTTP
		headers    http.Header
		bodyStream io.ReadCloser
	)

	if isRequest {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("reading request failed")
		}
		result.Method = request.Method
		result.URL = request.URL.String()
		headers = request.Header
		bodyStream = request.Body
	} else {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("reading response failed")
		}
		result.Method = ""
		result.URL = ""
		headers = response.Header
		bodyStream = response.Body
	}

	result.Headers = make(map[string]string)
	for headerName, headerValue := range headers {
		if openapi.IsUninterestingHeader(strings.ToLower(headerName)) {
			continue
		}
		result.Headers[headerName] = strings.Join(headerValue, ";")
	}

	if bodyStream != nil {
		body, _ := io.ReadAll(bodyStream)
		result.Body = string(body)
	} else {
		result.Body = ""
	}

	return &result, nil
}
