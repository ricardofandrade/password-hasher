package ph

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type PasswordHasher struct {
	uniqueId int64
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{}
}

func (pwHasher *PasswordHasher) hashPassword(password string) (string, int64) {
	id := atomic.AddInt64(&pwHasher.uniqueId, 1)
	hashed := sha512.Sum512([]byte(password))
	encoded := base64.StdEncoding.EncodeToString(hashed[:])
	return encoded, id
}

type PasswordStore struct {
	hashes   map[int64]string
	hashLock sync.RWMutex
	wg       sync.WaitGroup
}

func NewPasswordStore() *PasswordStore {
	return &PasswordStore{
		hashes: make(map[int64]string),
	}
}

func (store *PasswordStore) storePassword(hashed string, id int64) {
	log.Printf("Storing for %d ...", id)
	store.wg.Add(1)
	time.Sleep(5 * time.Second)
	defer store.hashLock.Unlock()
	store.hashLock.Lock()
	store.hashes[id] = hashed
	store.wg.Done()
	log.Printf("%d stored", id)
}

func (store *PasswordStore) retrievePassword(id int64) string {
	log.Printf("Getting for %d", id)
	defer store.hashLock.RUnlock()
	store.hashLock.RLock()
	if password, ok := store.hashes[id]; ok {
		return password
	}
	return ""
}

func (store *PasswordStore) waitPendingStores() {
	store.wg.Wait()
	log.Print("No more pending stores")
}

type PasswordHasherStats struct {
	queue chan int64
	times []int64
	lock  sync.RWMutex
}

func NewPasswordHasherStats() *PasswordHasherStats {
	return &PasswordHasherStats{
		queue: make(chan int64, 1),
		times: make([]int64, 0),
	}
}

func (phStats *PasswordHasherStats) addTiming(elapsed time.Duration) {
	phStats.queue <- elapsed.Microseconds()
}

func (phStats *PasswordHasherStats) generateStats() (total int64, avg int64) {
	defer phStats.lock.RUnlock()
	phStats.lock.RLock()
	if len(phStats.times) == 0 {
		return
	}
	var accumulated int64
	for _, microseconds := range phStats.times {
		accumulated += microseconds
	}
	total = int64(len(phStats.times))
	return total, accumulated / total
}

func (phStats *PasswordHasherStats) collectStats() {
	log.Print("Collecting stats...")
	ok := true
	for ok {
		var microseconds int64
		if microseconds, ok = <-phStats.queue; ok {
			log.Printf("Stats: %d", microseconds)
			phStats.lock.Lock()
			phStats.times = append(phStats.times, microseconds)
			phStats.lock.Unlock()
		}
	}
	log.Print("Done collecting stats")
}

func (phStats *PasswordHasherStats) stopCollecting() {
	close(phStats.queue)
}

func (server *PasswordHasherServer) hash(w http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	if server.stopping {
		stopErrorResponse(w)
		return
	}
	if req.Method != "POST" {
		methodErrorResponse(w)
		return
	}
	if err := req.ParseForm(); err != nil {
		_, errW := fmt.Fprintf(w, "Bad Form")
		logWriteError(errW)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	password := req.FormValue("password")
	hashed, id := server.pwHasher.hashPassword(password)
	go server.pwStore.storePassword(hashed, id)
	_, errW := fmt.Fprintf(w, "%d", id)
	logWriteError(errW)
	finishTime := time.Now()
	server.phStats.addTiming(finishTime.Sub(startTime))
}

func (server *PasswordHasherServer) getHash(w http.ResponseWriter, req *http.Request) {
	if server.stopping {
		stopErrorResponse(w)
		return
	}
	if req.Method != "GET" {
		methodErrorResponse(w)
		return
	}
	value := req.URL.Path[len("/hash/"):]
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		_, errW := fmt.Fprintf(w, "Invalid ID")
		logWriteError(errW)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	password := server.pwStore.retrievePassword(id)
	if password == "" {
		_, errW := fmt.Fprintf(w, "")
		logWriteError(errW)
		return
	}
	_, errW := fmt.Fprintf(w, "%s", password)
	logWriteError(errW)
}

func statsToJson(total, avg int64) ([]byte, error) {
	type Stats struct {
		Total   int64 `json:"total"`
		Average int64 `json:"average"`
	}
	return json.Marshal(&Stats{
		total, avg,
	})
}

func (server *PasswordHasherServer) getStats(w http.ResponseWriter, req *http.Request) {
	if server.stopping {
		stopErrorResponse(w)
		return
	}
	if req.Method != "GET" {
		methodErrorResponse(w)
		return
	}

	total, avg := server.phStats.generateStats()
	if data, err := statsToJson(total, avg); err != nil {
		_, errW := fmt.Fprintf(w, "Error")
		logWriteError(errW)
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		_, errW := w.Write(data)
		logWriteError(errW)
	}
}

func (server *PasswordHasherServer) shutdown(w http.ResponseWriter, req *http.Request) {
	if server.stopping {
		stopErrorResponse(w)
		return
	}
	if req.Method != "GET" {
		methodErrorResponse(w)
		return
	}
	server.done <- true
}

func logWriteError(errW error) {
	if errW != nil {
		log.Printf("ERROR: %v", errW)
	}
}

func methodErrorResponse(w http.ResponseWriter) {
	_, errW := fmt.Fprintf(w, "Not Supported")
	logWriteError(errW)
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func stopErrorResponse(w http.ResponseWriter) {
	_, errW := fmt.Fprintf(w, "Shutting Down")
	logWriteError(errW)
	w.WriteHeader(http.StatusServiceUnavailable)
}

type PasswordHasherServer struct {
	http     *http.Server
	stopping bool
	done     chan bool
	pwHasher *PasswordHasher
	pwStore  *PasswordStore
	phStats  *PasswordHasherStats
}

func (pwHasher *PasswordHasher) newServer() *PasswordHasherServer {
	mux := http.NewServeMux()
	server := &PasswordHasherServer{
		http:     &http.Server{Addr: ":8090", Handler: mux},
		stopping: false,
		done:     make(chan bool, 1),
		pwHasher: pwHasher,
		pwStore:  NewPasswordStore(),
		phStats:  NewPasswordHasherStats(),
	}
	mux.HandleFunc("/shutdown", server.shutdown)
	mux.HandleFunc("/stats", server.getStats)
	mux.HandleFunc("/hash", server.hash)
	mux.HandleFunc("/hash/", server.getHash)
	return server
}

func (server *PasswordHasherServer) start() {
	log.Print("Start server...")
	go server.phStats.collectStats()
	if err := server.http.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
}

type StoppedFunc func()

func (server *PasswordHasherServer) stop() StoppedFunc {
	server.phStats.stopCollecting()
	log.Print("Stopping server...")
	ctx, cancel := context.WithCancel(context.Background())
	if err := server.http.Shutdown(ctx); err != nil {
		panic(err)
	}
	log.Print("Done")
	return func() {
		server.pwStore.waitPendingStores()
		log.Print("Server Stopped")
		cancel()
	}
}

func (server *PasswordHasherServer) waitShutdown() {
	server.stopping = <-server.done
}

func (pwHasher *PasswordHasher) Run() {
	server := pwHasher.newServer()
	go server.start()
	server.waitShutdown()
	stopped := server.stop()
	defer stopped()
}
