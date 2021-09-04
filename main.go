package main

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

var uniqueId int64
var hashes = make(map[int64]string)

var times = make([]time.Duration, 0)
var stop bool
var done = make(chan bool, 1)

var stats = make(chan time.Duration, 1)
var hashLock = sync.RWMutex{}
var statsLock = sync.RWMutex{}
var wg sync.WaitGroup

func hashPassword(password string, id int64) {
	log.Printf("Hashing for %d", id)
	wg.Add(1)
	time.Sleep(5 * time.Second)
	hashed := sha512.Sum512([]byte(password))
	encoded := base64.StdEncoding.EncodeToString(hashed[:])
	defer hashLock.Unlock()
	hashLock.Lock()
	hashes[id] = encoded
	wg.Done()
	log.Printf("%d hashed", id)
}

func getPassword(id int64) string {
	log.Printf("Getting for %d", id)
	defer hashLock.RUnlock()
	hashLock.RLock()
	if password, ok := hashes[id]; ok {
		return password
	}
	return ""
}

type Stats struct {
	Total   int64 `json:"total"`
	Average int64 `json:"average"`
}

func generateStats() Stats {
	defer statsLock.RUnlock()
	statsLock.RLock()
	if len(times) == 0 {
		return Stats{}
	}
	var msSum int64
	for _, ts := range times {
		msSum += ts.Microseconds()
	}
	return Stats{
		Total:   uniqueId,
		Average: msSum / int64(len(times)),
	}
}

func hash(w http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	if stop {
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
	id := atomic.AddInt64(&uniqueId, 1)
	password := req.FormValue("password")
	go hashPassword(password, id)
	if _, errW := fmt.Fprintf(w, "%d", id); errW != nil {
		log.Printf("ERROR: %v", errW)
	}
	finishTime := time.Now()
	stats <- finishTime.Sub(startTime)
}

func getHash(w http.ResponseWriter, req *http.Request) {
	if stop {
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
	password := getPassword(id)
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

func getStats(w http.ResponseWriter, req *http.Request) {
	if stop {
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

	stats := generateStats()
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

func shutdown(w http.ResponseWriter, req *http.Request) {
	if stop {
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
	done <- true
}

func collectStats() {
	log.Print("Collecting stats...")
	wg.Add(1)
	ok := true
	for ok {
		var ts time.Duration
		if ts, ok = <-stats; ok {
			log.Printf("Stats: %d", ts.Microseconds())
			statsLock.Lock()
			times = append(times, ts)
			statsLock.Unlock()
		}
	}
	wg.Done()
	log.Print("No more stats")
}

func startServer(server *http.Server) {
	mux := http.NewServeMux()
	server = &http.Server{Addr: ":8090", Handler: mux}
	mux.HandleFunc("/shutdown", shutdown)
	mux.HandleFunc("/stats", getStats)
	mux.HandleFunc("/hash", hash)
	mux.HandleFunc("/hash/", getHash)

	log.Print("Start server...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
	log.Print("Server Stopped")
}

func stopServer(server *http.Server, ctx context.Context) {
	log.Print("Stopping server...")
	if err := server.Shutdown(ctx); err != nil {
		panic(err)
	}
	log.Print("Done")
}

func main() {
	var server http.Server
	go startServer(&server)
	go collectStats()
	stop = <-done
	close(stats)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopServer(&server, ctx)
	wg.Wait()
}
