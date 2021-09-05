package ph

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// PasswordHasherServer is an HTTP service that hashes passwords using the SHA512 algorithm, but which
// imposes a 5-second delay between the hash request and the available hash for... reasons :)
// The service also provides endpoints for stats and graceful shutdown.
type PasswordHasherServer struct {
	http     *http.Server
	stopping bool
	done     chan bool
	pwHasher *passwordHasher
	phStore  *passwordHashStore
	phStats  *passwordHasherStats
}

// NewPasswordHasherServer creates a new hasher server ready to use.
func NewPasswordHasherServer() *PasswordHasherServer {
	mux := http.NewServeMux()
	server := &PasswordHasherServer{
		http: &http.Server{
			Addr:    ":8090", // TODO: make it configurable?
			Handler: mux,
		},
		stopping: false,
		done:     make(chan bool, 1),
		pwHasher: newPasswordHasher(),
		phStore:  newPasswordHashStore(),
		phStats:  newPasswordHasherStats(),
	}
	mux.HandleFunc("/shutdown", server.shutdown)
	mux.HandleFunc("/stats", server.getStats)
	mux.HandleFunc("/hash", server.hash)
	mux.HandleFunc("/hash/", server.getHash)
	return server
}

// Run will start the service and wait indefinitely for a call to the shutdown endpoint.
func (server *PasswordHasherServer) Run() {
	go server.start()
	server.waitShutdown()
	stopped := server.stop()
	defer stopped()
}

// start will listen for incoming HTTP traffic, and accumulate any stats.
func (server *PasswordHasherServer) start() {
	log.Print("Start server...")
	go server.phStats.accumulateStats()
	if err := server.http.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
}

// StoppedFunc is returned from stop and should be called via defer.
type StoppedFunc func()

// stop will halt listening for HTTP traffic, cease accumulating stats, and wait until all password stores are completed.
func (server *PasswordHasherServer) stop() StoppedFunc {
	server.phStats.stopAccumulating()
	log.Print("Stopping server...")
	ctx, cancel := context.WithCancel(context.Background())
	if err := server.http.Shutdown(ctx); err != nil {
		panic(err)
	}
	log.Print("Done")
	return func() {
		server.phStore.waitPendingStores()
		log.Print("Server Stopped")
		cancel()
	}
}

// waitShutdown blocks until the respective signal is received.
func (server *PasswordHasherServer) waitShutdown() {
	server.stopping = <-server.done
}

// hash handles the password hashing and its delayed storage, accumulating the time elapsed to complete.
// The password is expected as a POST'ed form with a field called "password".
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

	// Hash the password and store it.
	// Note that the plain-text password (hopefully) dies with this callstack.
	// TODO: Maybe protect the memory around the plain-text password?
	hashed, id := server.pwHasher.hashPassword(password)
	server.phStore.storePassword(hashed, id)

	_, errW := fmt.Fprintf(w, "%d", id)
	logWriteError(errW)
	finishTime := time.Now()
	server.phStats.accumulateTiming(finishTime.Sub(startTime))
}

// getHash obtains the password hash for a given id in the URL path.
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
	password := server.phStore.retrievePassword(id)
	if password == "" {
		_, errW := fmt.Fprintf(w, "")
		logWriteError(errW)
		return
	}
	_, errW := fmt.Fprintf(w, "%s", password)
	logWriteError(errW)
}

// getStats returns the current server stats (`total` passwords and `average` hashing time) as JSON.
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
	if data, ok := statsToJson(total, avg); ok {
		_, errW := w.Write(data)
		logWriteError(errW)
	} else {
		_, errW := fmt.Fprintf(w, "Internal Error")
		logWriteError(errW)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// shutdown initiates the server graceful shutdown, after this all endpoints will stop to respond.
// The process may take up to 5 seconds to complete due to pending hash operations.
// FIXME: Anyone reaching this service can shut it down. Don't we want to protect this a bit more?
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
