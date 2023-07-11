package standard

import (
	"encoding/json"
	"encoding/xml"
	"net/http"

	"github.com/golangid/candi/candihelper"
)

const (
	ErrTitle  = "Something wrong"
	ErrSource = ""
)

// HTTPResponse default candi http response format
type HTTPResponse struct {
	Success bool        `json:"success,omitempty"`
	Code    int         `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
	Meta    interface{} `json:"meta,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Errors  []ErrRes    `json:"errors,omitempty"`
}

type ErrRes struct {
	Title  string      `json:"title"`
	Detail interface{} `json:"detail"`
	Source string      `json:"source"`
}

// NewHTTPResponse for create common response
func NewHTTPResponse(code int, message string, params ...interface{}) *HTTPResponse {
	commonResponse := new(HTTPResponse)
	metaVal := Meta{
		Message: message,
	}

	for _, param := range params {
		switch val := param.(type) {
		case *Meta, Meta:
			cast := val.(Meta)
			metaVal = Meta{
				Pagination: cast.Pagination,
				Filter:     cast.Filter,
				Message:    message,
			}
		case candihelper.MultiError:
			var (
				multiErrors []ErrRes
			)
			for key, multiErr := range val.ToMap() {
				multiErrs := ErrRes{
					Title:  ErrTitle,
					Detail: key + " : " + multiErr,
					Source: ErrSource,
				}
				multiErrors = append(multiErrors, multiErrs)
			}
			commonResponse.Errors = multiErrors
		case error:
			message, _ := json.Marshal(candihelper.NewMultiError().Append("detail", val).ToMap())
			commonResponse.Errors = []ErrRes{
				{
					Title:  ErrTitle,
					Detail: message,
					Source: ErrSource,
				},
			}
		default:
			commonResponse.Data = val
		}
	}

	commonResponse.Meta = metaVal
	commonResponse.Code = code

	if code >= http.StatusBadRequest && len(commonResponse.Errors) == 0 {
		commonResponse.Errors = []ErrRes{
			{
				Title:  ErrTitle,
				Detail: message,
				Source: ErrSource,
			},
		}
	}

	return commonResponse
}

// JSON for set http JSON response (Content-Type: application/json) with parameter is http response writer
func (resp *HTTPResponse) JSON(w http.ResponseWriter) error {
	w.Header().Set(candihelper.HeaderContentType, candihelper.HeaderMIMEApplicationJSON)
	w.WriteHeader(resp.Code)
	return json.NewEncoder(w).Encode(resp)
}

// XML for set http XML response (Content-Type: application/xml)
func (resp *HTTPResponse) XML(w http.ResponseWriter) error {
	w.Header().Set(candihelper.HeaderContentType, candihelper.HeaderMIMEApplicationXML)
	w.WriteHeader(resp.Code)
	return xml.NewEncoder(w).Encode(resp)
}
