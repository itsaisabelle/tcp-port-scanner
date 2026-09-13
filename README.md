# portscanner

A small, from-scratch TCP port scanner written in Go. It's a toy,
single-machine version of the idea behind large-scale internet scanning tools
like [ZMap](https://zmap.io/) (the research project out of the University of
Michigan that Censys grew out of): given a set of targets and a set of ports,
open as many TCP connections as possible in parallel to quickly find out
what's open, and optionally grab a banner to help identify the service.

## Why this project

Internet-scale scanners like ZMap don't check one host at a time — they use
massive concurrency and lightweight, stateless probing to sweep huge address
ranges quickly. This project applies that same core idea at a much smaller
scale: a worker-pool of goroutines that can each independently attempt a
connection, so scanning 1,000 host:port combinations takes about as long as
scanning a handful, instead of 1,000x as long.

## Features

- **Flexible targets**: a single IP (`127.0.0.1`) or a CIDR range
  (`192.168.1.0/28`), expanded into individual hosts.
- **Flexible port specs**: comma-separated ports, ranges, or a mix
  (`22,80,443,8000-8010`).
- **Concurrent scanning**: a configurable worker pool (goroutines +
  channels) so scans run in parallel rather than sequentially.
- **Configurable timeout**: tune how long to wait per connection attempt,
  trading speed for accuracy on slow or lossy networks.
- **Banner grabbing**: after a successful connect, optionally reads the
  first bytes a service sends unprompted (common for services like SSH,
  FTP, or SMTP) to help identify what's running on a port.

## Build

```
go build -o portscanner main.go
```

## Usage

```
./portscanner -target <ip-or-cidr> -ports <port-spec> [flags]
```

Flags:

| Flag        | Default     | Description                                             |
|-------------|-------------|----------------------------------------------------------|
| `-target`   | `127.0.0.1` | IP address or CIDR range to scan                          |
| `-ports`    | `1-1024`    | Ports to scan (comma list and/or ranges)                   |
| `-workers`  | `200`       | Number of concurrent goroutines                            |
| `-timeout`  | `800`       | Per-connection timeout, in milliseconds                    |
| `-banner`   | `true`      | Attempt to read a banner from open ports                   |

### Examples

Scan the common well-known ports on localhost:

```
./portscanner -target 127.0.0.1 -ports 1-1024
```

Scan a specific list of ports across a small subnet you control:

```
./portscanner -target 192.168.1.0/28 -ports 22,80,443,3306,8080
```

Scan quickly with more workers and a shorter timeout (useful on a fast local
network; less reliable over a slow/high-latency link):

```
./portscanner -target 10.0.0.0/24 -ports 1-65535 -workers 1000 -timeout 200
```

## How it works, briefly

1. **Target expansion** (`expandTargets`) turns the `-target` flag into a
   list of concrete IP strings, walking a CIDR block byte-by-byte if given a
   range, and trimming the network/broadcast addresses.
2. **Port expansion** (`expandPorts`) turns the `-ports` flag into a sorted,
   deduplicated list of integers, supporting both single ports and ranges.
3. **Worker pool**: a fixed number of goroutines read `(ip, port)` jobs off
   a channel and call `probe` on each one. This bounds how many sockets are
   open at once (avoiding resource exhaustion) while still running many
   probes in parallel.
4. **Probe**: attempts `net.DialTimeout("tcp", ...)`. If it succeeds, the
   port is open; if `-banner` is set, it then does a short, best-effort read
   to see if the service says anything on its own.
5. **Results** are collected back over a second channel, sorted, and printed.

## Scope and limitations (by design, for a learning project)

- **TCP connect scans only** — no SYN/stealth scanning, no UDP. A raw-socket
  SYN scanner would need elevated privileges and lower-level packet
  crafting; this project intentionally stays at the level of Go's standard
  `net` package to keep the code readable and dependency-free.
- **No OS/service fingerprinting beyond a raw banner read** — real tools
  (like Censys's or `nmap`) apply protocol-specific probes and pattern
  matching to identify exact software/versions.
- **Single-machine scale** — this scans dozens to thousands of hosts
  comfortably, not the entire IPv4 address space. ZMap achieves internet-wide
  scans by working below the OS TCP stack (custom packet transmission and
  asynchronous, stateless response handling) rather than opening a full
  socket per probe like this program does.

## ⚠️ Only scan systems you own or have explicit permission to test

Scanning hosts you don't own or don't have permission to probe can violate
laws (e.g., the U.S. Computer Fraud and Abuse Act) and most organizations'
acceptable-use policies, even for "just" a port scan. Use this against
`127.0.0.1`, your own LAN, or hosts/services you've explicitly stood up for
testing (e.g., a personal VM or a deliberately vulnerable practice target
like a local `DVWA` or `Metasploitable` instance).
