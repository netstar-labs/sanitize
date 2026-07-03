# sanitize examples

Runnable examples showing four ways to use [`sanitize`](../): as an in-process
library, behind an HTTP API, behind a Unix domain socket, and as an MCP tool.
A standalone [command-line filter](#command-line-filter) lives in [`../cmd`](../cmd).

| Example | Directory | Transport | Constructor |
| --- | --- | --- | --- |
| [Library](#library) | [`library/`](library) | in-process | all three modes |
| [HTTP server](#http-server) | [`httpserver/`](httpserver) | HTTP / JSON | `NewTLDSanitizer()` |
| [Unix socket](#unix-socket) | [`unixsocket/`](unixsocket) | Unix socket, line protocol | `NewTLDSanitizer()` |
| [MCP server](#mcp-server) | [`mcpserver/`](mcpserver) | JSON-RPC 2.0 over stdio | `NewTLDSanitizer()` |

`sanitize` exposes one `Sanitizer` type in three modes, selected at
construction: `NewSanitizer()` (rectify only), `NewIANASanitizer()` (iana.org),
and `NewTLDSanitizer()` (iana.org + publicsuffix.org).

All examples are part of the module, so run them straight from the repo root:

```sh
go run ./example/library
go run ./example/httpserver
go run ./example/unixsocket
go build -o sanitize-mcp ./example/mcpserver
```

## The TLD list (read once)

Every example except the rectify-only mode of `library` uses
`NewTLDSanitizer()`, which loads the
[IANA](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) and
[Public Suffix](https://publicsuffix.org/list/public_suffix_list.dat) lists.

- **First run fetches over the network** and caches the lists for 72h under
  `./.sanitize` (or `/var/sanitize` on linux). Later runs read the cache and start
  instantly. Offline with no cache, the TLD map is empty and every domain
  reports as unregistered.
- `ToHost` only *reads* the loaded map and idna profile — it never mutates
  shared state — so a single sanitizer is **safe to share across goroutines**
  (the HTTP and socket servers rely on this).

## Reading a result

`ToHost` rewrites the input string in place to its host form and returns flags:

| Field | Meaning |
| --- | --- |
| `okay` | passed basic validation |
| `ip`   | host is an IPv4/IPv6 literal (for IPs, `okay` means public/routable) |
| `www`  | a leading `www.` label was stripped |
| `port` | port number removed during rectification, e.g. `8443` — present only when a valid port (1-65535) was detected |
| `display` | unicode (U-label) form, e.g. `exämple.com` — present only when the host was converted to punycode |
| `apex` | eTLD+1, e.g. `example.co.uk` — present only when a registered tld was found |
| `tld`  | the tld, e.g. `co.uk` — present only when a registered tld was found |

`apex`/`tld` come from the `Result.Apex`/`Result.TLD` byte offsets and are
reported only when `TLD > 0` (a registered tld was matched). A domain with an
unknown tld (`one.0x4433`) or a bare public suffix (`co.uk`) has no registered
tld and reports `okay=false` from a tld-loaded sanitizer.

`display` carries `Result.Display`: for an idna input the host is rewritten to
its canonical punycode A-label (`www.exämple.com` → `xn--exmple-cua.com`) and
`display` preserves the human-readable form (`exämple.com`); the servers omit
the field for ascii hosts. Underscore service labels (`_dmarc.example.com`) are
rejected by default per STD3 — a sanitizer built with
`.AllowUnderscore(true)` accepts them (none of these examples enable it).

---

## Library

Direct, in-process use of the `Sanitizer` in all three modes: rectify-only
(`NewSanitizer`), IANA (`NewIANASanitizer`), and IANA + Public Suffix
(`NewTLDSanitizer`). Note how `test.co.uk` resolves differently — IANA knows
only `uk`, while Public Suffix recognizes `co.uk`.

```sh
go run ./example/library
```

```
== NewSanitizer — rectify only ==
test.co.uk                                 -> test.co.uk             okay=true
one.0x4433                                 -> one.0x4433             okay=true

== NewIANASanitizer — iana.org ==
(1437 tld entries)
test.co.uk                                 -> test.co.uk             host okay=true apex=co.uk tld=uk
one.0x4433                                 -> one.0x4433             okay=false

== NewTLDSanitizer — iana.org + publicsuffix.org ==
(10380 tld entries)
co.uk                                      -> co.uk                  okay=false
test.co.uk                                 -> test.co.uk             host okay=true apex=test.co.uk tld=co.uk
one.0x4433                                 -> one.0x4433             okay=false
```

## HTTP server

A small JSON API over HTTP. One `Sanitizer` (`NewTLDSanitizer()`) is shared
across all requests.

```sh
go run ./example/httpserver -addr :8080
```

```sh
# single url (GET)
curl -s 'http://localhost:8080/sanitize' --get --data-urlencode 'url=https://www.example.com:8443/path'

# batch (POST)
curl -s -X POST 'http://localhost:8080/sanitize' \
  -H 'Content-Type: application/json' \
  -d '{"urls":["blog.example.co.uk","10.0.0.1","100.10.10.10"]}'
```

```json
{
  "input": "https://www.example.com:8443/path",
  "host": "example.com",
  "okay": true,
  "ip": false,
  "www": true,
  "port": 8443,
  "apex": "example.com",
  "tld": "com"
}
```

Routes: `GET /sanitize?url=…`, `POST /sanitize` (`{"urls":[…]}`), and `GET /`
for usage.

## Unix socket

A line-oriented server over a Unix domain socket: send one raw url per line,
get one JSON result per line. Cleans up the socket file on `Ctrl-C`.

```sh
go run ./example/unixsocket -socket /tmp/sanitize.sock
```

```sh
printf 'https://www.example.com:8443/path\nblog.example.co.uk\n10.0.0.1\n' \
  | nc -U /tmp/sanitize.sock
```

```json
{"input":"https://www.example.com:8443/path","host":"example.com","okay":true,"ip":false,"www":true,"port":8443,"apex":"example.com","tld":"com"}
{"input":"blog.example.co.uk","host":"blog.example.co.uk","okay":true,"ip":false,"www":false,"apex":"example.co.uk","tld":"co.uk"}
{"input":"10.0.0.1","host":"10.0.0.1","okay":false,"ip":true,"www":false}
```

> `nc -U` is BSD/macOS netcat. On Linux use `ncat -U` or
> `socat - UNIX-CONNECT:/tmp/sanitize.sock`.

## MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
a single tool, `sanitize_host`. It speaks JSON-RPC 2.0 over stdio using only the
standard library — no SDK dependency — so any MCP host can launch it directly.
Protocol messages go to **stdout**; logs go to **stderr**.

```sh
go build -o sanitize-mcp ./example/mcpserver
```

**Tool** — `sanitize_host`

```json
{ "url": "<raw url or host>" }
```

returns a text block plus `structuredContent`:

```json
{ "input": "…", "host": "…", "okay": true, "ip": false, "www": true, "apex": "example.co.uk", "tld": "co.uk" }
```

### Try it by hand

The server reads newline-delimited JSON-RPC messages on stdin:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sanitize_host","arguments":{"url":"https://www.exämple.co.uk/path"}}}' \
  | ./sanitize-mcp
```

### Connect it to a host

**Claude Code** (CLI) — point it at the built binary:

```sh
claude mcp add sanitize -- /absolute/path/to/sanitize-mcp
```

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sanitize": {
      "command": "/absolute/path/to/sanitize-mcp"
    }
  }
}
```

The host launches the binary and manages its stdio; you don't run it yourself.
Once connected, the assistant can call `sanitize_host` to normalize and validate
urls. Use an absolute path, since the host sets its own working directory (which
is also where the TLD cache `.sanitize` directory is created).

---

## Command-line filter

[`../cmd`](../cmd) is a stdin/stdout filter (not under `example/`, but the same
package in practice). It reads one raw url per line and splits the stream:
usable registrable domains go to **stdout**, everything else to **stderr** — so
you can pipe a clean domain list onward and inspect the rejects separately.

```sh
go build -o sanitize ./cmd
printf 'https://www.example.com/path\nblog.example.com\none.0x4433\n100.10.10.10\n10.10.10.10\n' | ./sanitize
```

```
example.com          # stdout: valid domains, rectified to host form
blog.example.com
```
```
one.0x4433           # stderr: rejected — unregistered tld
100.10.10.10         # stderr: rejected — ip address (IP mode off)
10.10.10.10          # stderr: rejected — private / non-routable ip
```

Pass a **file path** as the first argument to read from a file instead of stdin.

Two environment toggles move a category from stderr to stdout, so you can keep
addresses or unusual tlds in the clean stream when you want them:

| Env | Effect |
| --- | --- |
| `IP=on` | retain ip addresses (route them to stdout) |
| `TLD=on` | retain hosts with an unregistered tld (route them to stdout) |

### Building and deploying (`build/sanitize`)

[`../build/sanitize`](../build/sanitize) cross-compiles the filter for
**linux/amd64** with the git version and revision (`git describe` /
`git rev-parse`) stamped into the binary via `-ldflags -X`. The stamp shows in
the usage report — `sanitize help` prints `sanitize v1.2.3 abc123def456 - …`,
while an unstamped `go run` or plain `go build` prints `sanitize dev unknown`.

Run it from the repo root:

```sh
build/sanitize            # build only -> build/install/sanitize
build/sanitize user@host  # also scp to the host and install to /usr/local/bin (sudo)
```

When no host argument is given, the script falls back to a `build/host` file
containing the target (one `user@host` line), if present — keep a default
deploy target there instead of typing it each time. After a deploy the
`build/install/` staging directory is removed; a build-only run leaves the
binary there. Both `build/host` and `build/install/` are git-ignored.
