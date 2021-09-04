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
	hashes   map[int64]string

	stats chan time.Duration
	times []time.Duration
	stop  bool
	done  chan bool

	hashLock  sync.RWMutex
	statsLock sync.RWMutex
	wg        sync.WaitGroup
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		uniqueId:  0,
		hashes:    make(map[int64]string),
		stats:     make(chan time.Duration, 1),
		times:     make([]time.Duration, 0),
		stop:      false,
		done:      make(chan bool, 1),
		hashLock:  sync.RWMutex{},
		statsLock: sync.RWMutex{},
		wg:        sync.WaitGroup{},
	}
}

func (pwHasher *PasswordHasher) hashPassword(password string, id int64) {
	log.Printf("Hashing for %d", id)
	pwHasher.wg.Add(1)
	time.Sleep(5 * time.Second)
	hashed := sha512.Sum512([]byte(password))
	encoded := base64.StdEncoding.EncodeToString(hashed[:])
	defer pwHasher.hashLock.Unlock()
	pwHasher.hashLock.Lock()
	pwHasher.hashes[id] = encoded
	pwHasher.wg.Done()
	log.Printf("%d hashed", id)
}

func (pwHasher *PasswordHasher) getPassword(id int64) string {
	log.Printf("Getting for %d", id)
	defer pwHasher.hashLock.RUnlock()
	pwHasher.hashLock.RLock()
	if password, ok := pwHasher.hashes[id]; ok {
		return password
	}
	return ""
}

type Stats struct {
	Total   int64 `json:"total"`
	Average int64 `json:"average"`
}

func (pwHasher *PasswordHasher) generateStats() Stats {
	defer pwHasher.statsLock.RUnlock()
	pwHasher.statsLock.RLock()
	if len(pwHasher.times) == 0 {
		return Stats{}
	}
	var msSum int64
	for _, ts := range pwHasher.times {
		msSum += ts.Microseconds()
	}
	return Stats{
		Total:   pwHasher.uniqueId,
		Average: msSum / int64(len(pwHasher.times)),
	}
}

func (pwHasher *PasswordHasher) hash(w http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	if pwHasher.stop {
		if _, errW := fmt.Fprintf(w, "Shutting Down"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if req.Method != "POST" {
		if _, errW := fmt.Fprintf(w, "Not Supported"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := req.ParseForm(); err != nil {
		if _, errW := fmt.Fprintf(w, "Bad Form"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := atomic.AddInt64(&pwHasher.uniqueId, 1)
	password := req.FormValue("password")
	go pwHasher.hashPassword(password, id)
	if _, errW := fmt.Fprintf(w, "%d", id); errW != nil {
		log.Printf("ERROR: %v", errW)
	}
	finishTime := time.Now()
	pwHasher.stats <- finishTime.Sub(startTime)
}

func (pwHasher *PasswordHasher) getHash(w http.ResponseWriter, req *http.Request) {
	if pwHasher.stop {
		if _, errW := fmt.Fprintf(w, "Shutting Down"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if req.Method != "GET" {
		if _, errW := fmt.Fprintf(w, "Not Supported"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	value := req.URL.Path[len("/hash/"):]
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		if _, errW := fmt.Fprintf(w, "Invalid ID"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	password := pwHasher.getPassword(id)
	if password == "" {
		if _, errW := fmt.Fprintf(w, ""); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		return
	}
	if _, errW := fmt.Fprintf(w, "%s", password); errW != nil {
		log.Printf("ERROR: %v", errW)
	}
}

func (pwHasher *PasswordHasher) getStats(w http.ResponseWriter, req *http.Request) {
	if pwHasher.stop {
		if _, errW := fmt.Fprintf(w, "Shutting Down"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if req.Method != "GET" {
		if _, errW := fmt.Fprintf(w, "Not Supported"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	stats := pwHasher.generateStats()
	if data, err := json.Marshal(&stats); err != nil {
		if _, errW := fmt.Fprintf(w, "Error"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		if _, errW := w.Write(data); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
	}
}

func (pwHasher *PasswordHasher) shutdown(w http.ResponseWriter, req *http.Request) {
	if pwHasher.stop {
		if _, errW := fmt.Fprintf(w, "Shutting Down"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if req.Method != "GET" {
		if _, errW := fmt.Fprintf(w, "Not Supported"); errW != nil {
			log.Printf("ERROR: %v", errW)
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	pwHasher.done <- true
}

func (pwHasher *PasswordHasher) collectStats() {
	log.Print("Collecting stats...")
	pwHasher.wg.Add(1)
	ok := true
	for ok {
		var ts time.Duration
		if ts, ok = <-pwHasher.stats; ok {
			log.Printf("Stats: %d", ts.Microseconds())
			pwHasher.statsLock.Lock()
			pwHasher.times = append(pwHasher.times, ts)
			pwHasher.statsLock.Unlock()
		}
	}
	pwHasher.wg.Done()
	log.Print("No more stats")
}

func (pwHasher *PasswordHasher) startServer(server *http.Server) {
	mux := http.NewServeMux()
	server = &http.Server{Addr: ":8090", Handler: mux}
	mux.HandleFunc("/shutdown", pwHasher.shutdown)
	mux.HandleFunc("/stats", pwHasher.getStats)
	mux.HandleFunc("/hash", pwHasher.hash)
	mux.HandleFunc("/hash/", pwHasher.getHash)

	log.Print("Start server...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
}

func (pwHasher *PasswordHasher) stopServer(server *http.Server, ctx context.Context) {
	log.Print("Stopping server...")
	if err := server.Shutdown(ctx); err != nil {
		panic(err)
	}
	log.Print("Done")
}

func (pwHasher *PasswordHasher) Run() {
	var server http.Server
	go pwHasher.startServer(&server)
	go pwHasher.collectStats()
	pwHasher.stop = <-pwHasher.done
	close(pwHasher.stats)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pwHasher.stopServer(&server, ctx)
	pwHasher.wg.Wait()
	log.Print("Server Stopped")
}
