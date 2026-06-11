package modules

import (
	"net/http"

	"github.com/mijelblack677-ctrl/aegis/internal/parser"
	"github.com/mijelblack677-ctrl/aegis/internal/output"
)

type RequestResponsePair struct {
	Request      *http.Request
	Response     *http.Response
	RequestBody  []byte
	ResponseBody []byte
	ParsedData   *parser.ParseResult
}

type Module interface {
	Name() string
	Run(pair *RequestResponsePair) ([]*output.Vulnerability, error)
	IsPassive() bool
}