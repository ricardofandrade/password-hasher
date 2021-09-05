package ph

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func Test_NewPasswordHasherServer(t *testing.T) {
	server := NewPasswordHasherServer(nil)
	if server.pwHasher == nil {
		t.Error("Expected hasher to not be nil")
	}
	if server.phStore == nil {
		t.Error("Expected store to not be nil")
	}
	if server.phStats == nil {
		t.Error("Expected stats to not be nil")
	}
	if server.stopping == true {
		t.Error("Expected to not be stopping")
	}

	// Enforce channel len 1
	server.done <- true

	full := false
	select {
	case server.done <- false: // Put 2 in the channel unless it is full
	default:
		full = true
	}
	if !full {
		t.Error("Expected queue to hold only a single value")
	}
}

func Test_stoppingResponse(t *testing.T) {
	server := &PasswordHasherServer{stopping: true}

	w := httptest.NewRecorder()
	server.hash(w, &http.Request{})
	Test_stopErrorResponse(t)

	w = httptest.NewRecorder()
	server.getHash(w, &http.Request{})
	Test_stopErrorResponse(t)

	w = httptest.NewRecorder()
	server.getStats(w, &http.Request{})
	Test_stopErrorResponse(t)

	w = httptest.NewRecorder()
	server.shutdownServer(w, &http.Request{})
	Test_stopErrorResponse(t)
}

func Test_methodResponse(t *testing.T) {
	server := &PasswordHasherServer{}

	w := httptest.NewRecorder()
	server.hash(w, &http.Request{Method: http.MethodGet})
	Test_methodErrorResponse(t)

	w = httptest.NewRecorder()
	server.getHash(w, &http.Request{Method: http.MethodPost})
	Test_methodErrorResponse(t)

	w = httptest.NewRecorder()
	server.getStats(w, &http.Request{Method: http.MethodPost})
	Test_methodErrorResponse(t)

	w = httptest.NewRecorder()
	server.shutdownServer(w, &http.Request{Method: http.MethodPost})
	Test_methodErrorResponse(t)
}

func Test_hashBadForm(t *testing.T) {
	server := &PasswordHasherServer{}

	w := httptest.NewRecorder()
	server.hash(w, &http.Request{Method: http.MethodPost})

	if w.Body.String() != "Bad Form" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_getHashInvalidId(t *testing.T) {
	server := &PasswordHasherServer{}

	w := httptest.NewRecorder()
	server.getHash(w, &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/hash/bogus"}})

	if w.Body.String() != "Invalid ID" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_hash(t *testing.T) {
	server := &PasswordHasherServer{
		pwHasher: &MockHasher{
			expected: "test",
			t:        t,
		},
		phStore: &MockStore{
			hash:     "test",
			expected: "very-hashed",
			id:       42,
			t:        t,
		},
		phStats: &MockStats{
			t: t,
		},
	}

	w := httptest.NewRecorder()
	buf := bytes.NewReader([]byte("password=test"))
	r, err := http.NewRequest(http.MethodPost, "", buf)
	if err != nil {
		panic(err)
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	server.hash(w, r)

	if w.Body.String() != "42" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_getHashNone(t *testing.T) {
	server := &PasswordHasherServer{
		phStore: &MockStore{
			hash: "",
			id:   42,
			t:    t,
		},
	}
	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "/hash/42", nil)
	if err != nil {
		panic(err)
	}
	server.getHash(w, r)

	if w.Body.String() != "" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_getHash(t *testing.T) {
	server := &PasswordHasherServer{
		phStore: &MockStore{
			hash: "test",
			id:   42,
			t:    t,
		},
	}
	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "/hash/42", nil)
	if err != nil {
		panic(err)
	}
	server.getHash(w, r)

	if w.Body.String() != "test" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_getStats(t *testing.T) {
	server := &PasswordHasherServer{
		phStats: &MockStats{
			total: 10,
			avg:   33,
		},
	}
	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "", nil)
	if err != nil {
		panic(err)
	}
	server.getStats(w, r)

	if w.Body.String() != `{"total":10,"average":33}` {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_shutdownServer(t *testing.T) {
	server := NewPasswordHasherServer(nil)
	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "", nil)
	if err != nil {
		panic(err)
	}
	server.shutdownServer(w, r)
	if w.Body.String() != "" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
	// shouldn't block
	server.waitShutdown()
}

func Test_NewPasswordHasherServerHandler(t *testing.T) {
	server := NewPasswordHasherServer(nil)
	server.pwHasher = &MockHasher{
		expected: "test",
		t:        t,
	}
	server.phStore = &MockStore{
		hash:     "test",
		expected: "very-hashed",
		id:       42,
		t:        t,
	}
	server.phStats = &MockStats{
		total: 10,
		avg:   33,
		t:     t,
	}
	w := httptest.NewRecorder()
	buf := bytes.NewReader([]byte("password=test"))
	r, err := http.NewRequest(http.MethodPost, "/hash", buf)
	if err != nil {
		panic(err)
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	server.http.Handler.ServeHTTP(w, r)
	if w.Body.String() != "42" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, "/hash/42", buf)
	if err != nil {
		panic(err)
	}

	server.http.Handler.ServeHTTP(w, r)
	if w.Body.String() != "test" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, "/stats", buf)
	if err != nil {
		panic(err)
	}

	server.http.Handler.ServeHTTP(w, r)
	if w.Body.String() != `{"total":10,"average":33}` {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, "/shutdown", buf)
	if err != nil {
		panic(err)
	}

	server.http.Handler.ServeHTTP(w, r)
	if w.Body.String() != "" {
		t.Errorf("Unexpected body, got %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Errorf("Unexpected code, got %d", w.Code)
	}
}

func Test_Run(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)

	server := NewPasswordHasherServer(logger)
	go server.Run()
	time.Sleep(time.Second)
	server.shutdown()
	time.Sleep(time.Second)

	if buf.String() != "Start server...\nCollecting stats...\nStopping server...\nDone collecting stats\nDone\nNo more pending stores\nServer Stopped\n" {
		t.Errorf("Unexpected log: %s", buf.String())
	}
}

type MockHasher struct {
	expected string
	t        *testing.T
}

func (m *MockHasher) hashPassword(password string) (string, int64) {
	if m.expected != password {
		m.t.Errorf("Unexpected password: %s", password)
	}
	return "very-hashed", 42
}

type MockStore struct {
	hash     string
	expected string
	id       int64
	pending  bool
	t        *testing.T
}

func (m *MockStore) storePassword(hashed string, id int64) {
	if hashed != m.expected {
		m.t.Errorf("Unexpected hashed: %s", hashed)
	}
	if id != m.id {
		m.t.Errorf("Unexpected id: %d", id)
	}
}

func (m *MockStore) retrievePassword(id int64) string {
	if id != m.id {
		m.t.Errorf("Unexpected id: %d", id)
	}
	return m.hash
}

func (m *MockStore) waitPendingStores() {
	m.pending = true
}

type MockStats struct {
	total int64
	avg   int64
	acc   bool
	t     *testing.T
}

func (m *MockStats) accumulateTiming(elapsed time.Duration) {
	ms := elapsed.Microseconds()
	if ms > 100 {
		m.t.Errorf("Unexpected elapsed time: %dms", ms)
	}
}

func (m *MockStats) generateStats() (int64, int64) {
	return m.total, m.avg
}

func (m *MockStats) startAccumulating() {
	m.acc = true
}

func (m *MockStats) stopAccumulating() {
	m.acc = false
}
