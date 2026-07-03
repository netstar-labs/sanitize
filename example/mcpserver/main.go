// Command mcpserver is a minimal Model Context Protocol (MCP) server that exposes
// the sanitize package as a tool. It speaks JSON-RPC 2.0 over stdio (one
// newline-delimited JSON message per line) using only the standard library, so
// an MCP host such as Claude Desktop or Claude Code can launch it directly.
//
// Protocol messages travel on stdout; logs go to stderr. The server implements
// the handshake (initialize) plus tools/list and tools/call.
//
// Tool:
//
//	sanitize_host { "url": "<raw url or host>" }
//
//	go build -o sanitize-mcp ./example/mcpserver
package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"

	"github.com/netstar-labs/sanitize"
)

// defaultProtocol is advertised when the client does not request a version.
const defaultProtocol = "2025-06-18"

// rpcRequest is an incoming JSON-RPC 2.0 message. A missing id marks it a
// notification, which must not be answered.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func main() {

	log.SetOutput(os.Stderr) // stdout is reserved for protocol messages

	s := sanitize.NewTLDSanitizer()
	log.Printf("sanitize mcp server ready; %d tld entries", s.Len())

	enc := json.NewEncoder(os.Stdout) // Encode writes one JSON object + newline

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1024*1024) // allow large messages
	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue // ignore malformed input
		}

		resp := dispatch(&req, s)
		if resp == nil {
			continue // notification: no reply
		}
		if err := enc.Encode(resp); err != nil {
			log.Printf("write: %v", err)
			return
		}
	}
}

// dispatch routes a request and returns the full response object, or nil for
// notifications that must not be answered.
func dispatch(req *rpcRequest, s *sanitize.Sanitizer) map[string]any {
	if len(req.ID) == 0 {
		return nil // notification (e.g. notifications/initialized)
	}

	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	switch req.Method {
	case "initialize":
		resp["result"] = initialize(req.Params)
	case "tools/list":
		resp["result"] = map[string]any{"tools": tools()}
	case "tools/call":
		resp["result"] = callTool(req.Params, s)
	case "ping":
		resp["result"] = map[string]any{}
	default:
		resp["error"] = map[string]any{
			"code":    -32601,
			"message": "method not found: " + req.Method,
		}
	}
	return resp
}

func initialize(params json.RawMessage) map[string]any {
	protocol := defaultProtocol
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
		protocol = p.ProtocolVersion // echo the version the client asked for
	}
	return map[string]any{
		"protocolVersion": protocol,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo": map[string]any{
			"name":    "sanitize",
			"version": "1.0.0",
		},
	}
}

func tools() []map[string]any {
	return []map[string]any{{
		"name": "sanitize_host",
		"description": "Rectify a raw url to its host form and validate it. " +
			"Reports whether the host is okay, whether it is an IP, and (for " +
			"domains) the apex (eTLD+1) and tld.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url": map[string]any{
					"type":        "string",
					"description": "raw url or host, e.g. https://www.example.com/path",
				},
			},
			"required": []string{"url"},
		},
	}}
}

func callTool(params json.RawMessage, s *sanitize.Sanitizer) map[string]any {
	var call struct {
		Name      string `json:"name"`
		Arguments struct {
			URL string `json:"url"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return toolError("invalid params: " + err.Error())
	}
	if call.Name != "sanitize_host" {
		return toolError("unknown tool: " + call.Name)
	}
	if call.Arguments.URL == "" {
		return toolError(`missing required argument "url"`)
	}

	host := call.Arguments.URL // copy: ToHost rewrites the string in place
	r := s.ToHost(&host)
	out := map[string]any{
		"input": call.Arguments.URL,
		"host":  host,
		"okay":  r.Okay,
		"ip":    r.IP,
		"www":   r.WWW,
	}
	if r.Port > 0 { // a port was removed during rectification
		out["port"] = r.Port
	}
	if r.TLD > 0 { // a registered tld was found (implies a valid domain)
		out["apex"] = host[r.Apex:]
		out["tld"] = host[r.TLD:]
	}
	if r.Display != "" { // set only when the host was converted to punycode
		out["display"] = r.Display
	}

	text, _ := json.MarshalIndent(out, "", "  ")
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(text)}},
		"structuredContent": out,
		"isError":           false,
	}
}

func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}
