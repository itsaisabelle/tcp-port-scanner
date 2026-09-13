// portscanner is a small, educational TCP port scanner.
//
// It is a toy, single-machine version of the idea behind large-scale internet
// scanning tools like ZMap: given a set of targets (single IPs or a CIDR
// range) and a set of ports, quickly attempt TCP connections to find open
// ports, optionally grabbing a banner (the first bytes a service sends) to
// help identify what's running there.
//
// This is intended for scanning hosts you own or have explicit permission to
// scan (e.g. localhost, a home lab VM, or a service you control). Scanning
// systems you don't own or have permission to test can be illegal.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// result holds the outcome of probing a single host:port combination.
type result struct {
	ip     string
	port   int
	open   bool
	banner string
}

func main() {
	targetFlag := flag.String("target", "127.0.0.1", "Target IP address or CIDR range (e.g. 127.0.0.1 or 192.168.1.0/28)")
	portsFlag := flag.String("ports", "1-1024", "Ports to scan: comma-separated list and/or ranges (e.g. 22,80,443 or 1-1024)")
	workers := flag.Int("workers", 200, "Number of concurrent workers (goroutines)")
	timeoutMS := flag.Int("timeout", 800, "Per-connection timeout in milliseconds")
	grabBanner := flag.Bool("banner", true, "Attempt to read a short banner from open ports")
	flag.Parse()

	ips, err := expandTargets(*targetFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing target: %v\n", err)
		os.Exit(1)
	}

	ports, err := expandPorts(*portsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing ports: %v\n", err)
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutMS) * time.Millisecond
	totalJobs := len(ips) * len(ports)
	fmt.Printf("Scanning %d host(s) x %d port(s) = %d probes, %d workers, %v timeout\n\n",
		len(ips), len(ports), totalJobs, *workers, timeout)

	jobs := make(chan struct {
		ip   string
		port int
	}, *workers)
	results := make(chan result, *workers)

	var wg sync.WaitGroup
	start := time.Now()

	// Worker pool: each worker pulls (ip, port) jobs and attempts a TCP
	// connect. This is the "concurrency" that lets us probe many
	// host:port pairs in parallel instead of one at a time.
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results <- probe(job.ip, job.port, timeout, *grabBanner)
			}
		}()
	}

	// Feed jobs.
	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				jobs <- struct {
					ip   string
					port int
				}{ip, port}
			}
		}
		close(jobs)
	}()

	// Close results channel once all workers finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	var open []result
	for r := range results {
		if r.open {
			open = append(open, r)
		}
	}

	sort.Slice(open, func(i, j int) bool {
		if open[i].ip != open[j].ip {
			return open[i].ip < open[j].ip
		}
		return open[i].port < open[j].port
	})

	elapsed := time.Since(start)
	fmt.Printf("Done in %v. Open ports found: %d\n\n", elapsed, len(open))
	for _, r := range open {
		if r.banner != "" {
			fmt.Printf("%-15s : %-5d OPEN   banner: %q\n", r.ip, r.port, r.banner)
		} else {
			fmt.Printf("%-15s : %-5d OPEN\n", r.ip, r.port)
		}
	}
}

// probe attempts a single TCP connection to ip:port. If it connects within
// the timeout, the port is considered open. If grabBanner is set, it then
// tries to read a small amount of data the service may send immediately
// after connecting (many services, like SSH or SMTP, announce themselves
// unprompted).
func probe(ip string, port int, timeout time.Duration, grabBanner bool) result {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return result{ip: ip, port: port, open: false}
	}
	defer conn.Close()

	r := result{ip: ip, port: port, open: true}

	if grabBanner {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		reader := bufio.NewReader(conn)
		buf := make([]byte, 256)
		n, _ := reader.Read(buf)
		if n > 0 {
			banner := strings.TrimSpace(string(buf[:n]))
			banner = strings.ReplaceAll(banner, "\r", " ")
			banner = strings.ReplaceAll(banner, "\n", " ")
			r.banner = banner
		}
	}

	return r
}

// expandTargets turns a target spec (single IP or CIDR notation) into a
// concrete list of IP addresses to scan.
func expandTargets(spec string) ([]string, error) {
	if !strings.Contains(spec, "/") {
		if net.ParseIP(spec) == nil {
			return nil, fmt.Errorf("invalid IP address: %s", spec)
		}
		return []string{spec}, nil
	}

	ip, ipnet, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR range: %w", err)
	}

	var ips []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
		ips = append(ips, cur.String())
	}

	// Drop network and broadcast addresses for ranges bigger than a /31,
	// mirroring how most scanners treat a CIDR block in practice.
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// incIP increments an IP address in place, used to walk a CIDR range byte by
// byte (e.g. 192.168.1.1 -> 192.168.1.2 -> ... -> 192.168.1.255 -> 192.168.2.0).
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// expandPorts parses a port spec like "22,80,443,8000-8010" into a sorted,
// deduplicated slice of port numbers.
func expandPorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	var ports []int

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			hi, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	sort.Ints(ports)
	return ports, nil
}
