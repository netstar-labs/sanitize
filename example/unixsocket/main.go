// Command unixsocket serves the sanitize package over a Unix domain socket using
// a simple newline-delimited protocol: send one raw url per line and receive one
// JSON result per line.
//
//	go run ./example/unixsocket -socket /tmp/sanitize.sock
//	printf 'https://www.example.com/path\n10.0.0.1\n' | nc -U /tmp/sanitize.sock
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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

	socket := flag.String("socket", "/tmp/sanitize.sock", "unix socket path")
	flag.Parse()

	s := sanitize.NewTLDSanitizer()
	log.Printf("loaded %d tld entries", s.Len())

	// clear any stale socket left behind by a previous run
	os.Remove(*socket)

	l, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on unix:%s", *socket)

	// graceful shutdown: closing the listener unblocks Accept, then remove the
	// socket file so the next run starts clean.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutting down")
		l.Close()
		os.Remove(*socket)
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go handle(conn, s)
	}
}

func handle(conn net.Conn, s *sanitize.Sanitizer) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // allow long lines
	enc := json.NewEncoder(conn)                        // Encode writes one compact line per message
	for scanner.Scan() {
		raw := scanner.Text()
		if raw == "" {
			continue
		}
		host := raw // copy: ToHost rewrites the string in place
		r := s.ToHost(&host)
		out := result{Input: raw, Host: host, Okay: r.Okay, IP: r.IP, WWW: r.WWW, Port: r.Port, Display: r.Display}
		if r.TLD > 0 { // a registered tld was found (implies a valid domain)
			out.Apex = host[r.Apex:]
			out.TLD = host[r.TLD:]
		}
		enc.Encode(out)
	}
}
