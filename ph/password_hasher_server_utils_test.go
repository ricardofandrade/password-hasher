package ph

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_statsToJson(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)

	json, ok := statsToJson(logger, 10, 33)
	if !ok {
		t.Error("Expected ok")
	} else if string(json) != `{"total":10,"average":33}` {
		t.Errorf("Unexpect JSON: %s", json)
	}
}

func Test_logWriteError(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)

	logWriteError(logger, nil)
	if buf.String() != "" {
		t.Errorf("Expected no logs, got: %s", buf.String())
	}

	logWriteError(logger, errors.New("error"))
	if buf.String() != "ERROR: error\n" {
		t.Errorf("Expected error logs, got: %s", buf.String())
	}
}

func Test_methodErrorResponse(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)
	w := httptest.NewRecorder()
	methodErrorResponse(logger, w)

	if w.Body.String() != "Not Supported" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_stopErrorResponse(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)
	w := httptest.NewRecorder()
	stopErrorResponse(logger, w)

	if w.Body.String() != "Shutting Down" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}
