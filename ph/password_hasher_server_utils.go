package ph

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// statsToJson converts the given total/avg stats into a JSON string.
// Return false if the conversion fails (very unlikely).
func statsToJson(total, avg int64) ([]byte, bool) {
	type Stats struct {
		Total   int64 `json:"total"`
		Average int64 `json:"average"`
	}
	data, errJ := json.Marshal(&Stats{
		total, avg,
	})
	if errJ != nil {
		log.Printf("ERROR: %v", errJ)
		return nil, false
	}
	return data, true
}

// logWriteError is a shorthand to check for write errors, reporting those in the log.
func logWriteError(errW error) {
	if errW != nil {
		log.Printf("ERROR: %v", errW)
	}
}

// methodErrorResponse is a shorthand to return HTTP 405 when using a non-supported HTTP method.
func methodErrorResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, errW := fmt.Fprintf(w, "Not Supported")
	logWriteError(errW)
}

// stopErrorResponse is a shorthand to return HTTP 503 if the service is stopping.
func stopErrorResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusServiceUnavailable)
	_, errW := fmt.Fprintf(w, "Shutting Down")
	logWriteError(errW)
}
