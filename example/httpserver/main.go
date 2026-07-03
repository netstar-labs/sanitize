// Command httpserver exposes the sanitize package over HTTP as a small JSON API.
//
//	GET  /sanitize?url=<raw>       sanitize a single url
//	POST /sanitize  {"urls":[…]}   sanitize a batch
//
// A single Sanitizer is shared across all requests: ToHost only reads the
// loaded tld map and idna profile (it never mutates shared state), so it is
// safe for concurrent use.
//
//	go run ./example/httpserver -addr :8080
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/netstar-labs/sanitize"
)

type result struct {
	Input   string `json:"input"`
	Host    string `json:"host"`
	Okay    bool   `json:"okay"`
	IP      bool   `json:"ip"`
	WWW     bool   `json:"www"`
	Port    int    `json:"port,omitempty"` // port removed during rectification
	Apex    string `json:"apex,omitempty"`
	TLD     string `json:"tld,omitempty"`
	Display string `json:"display,omitempty"` // unicode form, set only when punycoded
}

func main() {

	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	// network on first run; cached 72h under ./.sanitize (or /var/sanitize on linux)
	s := sanitize.NewTLDSanitizer()
	log.Printf("loaded %d tld entries", s.Len())

	sanitizeOne := func(raw string) result {
		host := raw // copy: ToHost rewrites the string in place
		r := s.ToHost(&host)
		out := result{Input: raw, Host: host, Okay: r.Okay, IP: r.IP, WWW: r.WWW, Port: r.Port, Display: r.Display}
		if r.TLD > 0 { // a registered tld was found (implies a valid domain)
			out.Apex = host[r.Apex:]
			out.TLD = host[r.TLD:]
		}
		return out
	}

	mux := http.NewServeMux()

	// GET /sanitize?url=https://www.example.com/path
	mux.HandleFunc("GET /sanitize", func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("url")
		if raw == "" {
			http.Error(w, `missing "url" query parameter`, http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, sanitizeOne(raw))
	})

	// POST /sanitize  body: {"urls":["example.com","10.0.0.1"]}
	mux.HandleFunc("POST /sanitize", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // cap the request body at 1 MiB
		var body struct {
			URLs []string `json:"urls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json body", http.StatusBadRequest)
			return
		}
		out := make([]result, 0, len(body.URLs))
		for _, raw := range body.URLs {
			out = append(out, sanitizeOne(raw))
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": out})
	})

	// GET / usage
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, usage)
	})

	log.Printf("listening on http://localhost%s", *addr)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

const usage = `sanitize http example

GET  /sanitize?url=https://www.example.com/path
POST /sanitize   {"urls":["example.com","10.0.0.1"]}
`
