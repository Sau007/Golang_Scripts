package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// === configuration & required headers ===
var requiredHeaders = []string{
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"Referrer-Policy",
	"Permissions-Policy",
}

// === result types ===
type HeaderResult struct {
	URL            string            `json:"url"`
	Status         string            `json:"status"`
	MissingHeaders []string          `json:"missing_headers"`
	Headers        map[string]string `json:"headers"`
	DurationMs     int64             `json:"duration_ms"`
	RiskScore      int               `json:"risk_score"`
	RiskLevel      string            `json:"risk_level"`
	TLS            *TLSReport        `json:"tls,omitempty"`
	Error          string            `json:"error,omitempty"`
}

type TLSReport struct {
	PeerAddresses   []string `json:"peer_addresses,omitempty"`
	CertIssuer      string   `json:"cert_issuer,omitempty"`
	CertSubject     string   `json:"cert_subject,omitempty"`
	NotBefore       string   `json:"not_before,omitempty"`
	NotAfter        string   `json:"not_after,omitempty"`
	DaysUntilExpiry int      `json:"days_until_expiry,omitempty"`
	TLSVersion      string   `json:"tls_version,omitempty"`
	CipherSuite     string   `json:"cipher_suite,omitempty"`
}

type PortResult struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Open     bool   `json:"open"`
	Duration int64  `json:"duration_ms"`
	Error    string `json:"error,omitempty"`
}

type CombinedReport struct {
	Headers []HeaderResult `json:"headers,omitempty"`
	Ports   []PortResult   `json:"ports,omitempty"`
}

// === utilities ===
func parsePorts(portsArg string) ([]int, error) {
	if portsArg == "" {
		return nil, nil
	}
	parts := strings.Split(portsArg, ",")
	out := []int{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			rp := strings.SplitN(p, "-", 2)
			if len(rp) != 2 {
				continue
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rp[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rp[1]))
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for i := start; i <= end; i++ {
				out = append(out, i)
			}
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		out = append(out, v)
	}
	return out, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var lines []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

func scoreAndLevel(missing int) (int, string) {
	score := missing * 15
	if score > 100 {
		score = 100
	}
	var level string
	switch {
	case score <= 20:
		level = "Secure"
	case score <= 60:
		level = "Moderate"
	default:
		level = "High Risk"
	}
	return score, level
}

// === TLS helpers ===
func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func cipherSuiteString(id uint16) string {
	return fmt.Sprintf("0x%x", id)
}

func fetchTLSInfo(host string, timeoutSec int) (*TLSReport, error) {
	addr := host
	if !strings.Contains(host, ":") {
		addr = net.JoinHostPort(host, "443")
	}
	d := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	tr := &TLSReport{
		TLSVersion:  tlsVersionString(state.Version),
		CipherSuite: cipherSuiteString(state.CipherSuite),
	}
	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		tr.CertIssuer = c.Issuer.CommonName
		tr.CertSubject = c.Subject.CommonName
		tr.NotBefore = c.NotBefore.UTC().Format(time.RFC3339)
		tr.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
		tr.DaysUntilExpiry = int(time.Until(c.NotAfter).Hours() / 24)
	}
	return tr, nil
}

// === HTTP header scan with retries ===
func doRequestWithRetries(client *http.Client, req *http.Request, retries int) (*http.Response, error) {
	var resp *http.Response
	var err error
	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			return resp, nil
		}
		time.Sleep(time.Duration(200*(attempt+1)) * time.Millisecond)
	}
	return nil, err
}

func extractHeaders(resp *http.Response) map[string]string {
	m := map[string]string{}
	for k, v := range resp.Header {
		m[k] = strings.Join(v, "; ")
	}
	return m
}

func scanURL(target string, timeoutSec, retries int) HeaderResult {
	start := time.Now()
	result := HeaderResult{URL: target, Headers: map[string]string{}}

	u, err := url.Parse(target)
	if err != nil {
		result.Error = fmt.Sprintf("invalid url: %v", err)
		result.DurationMs = time.Since(start).Milliseconds()
		return result
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	host := u.Hostname()
	tlsinfo, _ := fetchTLSInfo(host, timeoutSec)
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		result.Error = err.Error()
		result.DurationMs = time.Since(start).Milliseconds()
		return result
	}
	req.Header.Set("User-Agent", "GoSec-Pro/3.0")
	resp, err := doRequestWithRetries(client, req, retries)
	if err != nil {
		result.Error = err.Error()
		result.DurationMs = time.Since(start).Milliseconds()
		if tlsinfo != nil {
			result.TLS = tlsinfo
		}
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.Status
	result.Headers = extractHeaders(resp)
	for _, h := range requiredHeaders {
		if _, ok := result.Headers[h]; !ok {
			result.MissingHeaders = append(result.MissingHeaders, h)
		}
	}
	result.RiskScore, result.RiskLevel = scoreAndLevel(len(result.MissingHeaders))
	result.DurationMs = time.Since(start).Milliseconds()
	if tlsinfo != nil {
		result.TLS = tlsinfo
	}
	return result
}

// === concurrent scanners ===
func workerScan(jobs <-chan string, results chan<- HeaderResult, timeout, retries, delayMs int, wg *sync.WaitGroup) {
	defer wg.Done()
	for t := range jobs {
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
		results <- scanURL(t, timeout, retries)
	}
}

func scanFromFile(input string, concurrency, timeout, retries, delayMs int) ([]HeaderResult, error) {
	lines, err := readLines(input)
	if err != nil {
		return nil, err
	}
	jobs := make(chan string, len(lines))
	results := make(chan HeaderResult, len(lines))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go workerScan(jobs, results, timeout, retries, delayMs, &wg)
	}
	for _, l := range lines {
		jobs <- l
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	var out []HeaderResult
	for r := range results {
		out = append(out, r)
	}
	return out, nil
}

// === port scanner ===
func workerPort(host string, jobs <-chan int, results chan<- PortResult, timeoutMs int, wg *sync.WaitGroup) {
	defer wg.Done()
	for p := range jobs {
		start := time.Now()
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
		if err != nil {
			results <- PortResult{Host: host, Port: p, Open: false, Duration: time.Since(start).Milliseconds(), Error: err.Error()}
			continue
		}
		_ = conn.Close()
		results <- PortResult{Host: host, Port: p, Open: true, Duration: time.Since(start).Milliseconds()}
	}
}

func scanPorts(host string, ports []int, concurrency, timeoutMs int) ([]PortResult, error) {
	if host == "" {
		return nil, fmt.Errorf("host required")
	}
	jobs := make(chan int, len(ports))
	results := make(chan PortResult, len(ports))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go workerPort(host, jobs, results, timeoutMs, &wg)
	}
	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	var out []PortResult
	for r := range results {
		out = append(out, r)
	}
	return out, nil
}

// === output helpers ===
func saveJSON(path string, v interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func saveCSVHeaders(path string, data []HeaderResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"url", "status", "risk_score", "risk_level", "missing_headers", "duration_ms", "tls_not_after"})
	for _, r := range data {
		notAfter := ""
		if r.TLS != nil {
			notAfter = r.TLS.NotAfter
		}
		_ = w.Write([]string{
			r.URL,
			r.Status,
			strconv.Itoa(r.RiskScore),
			r.RiskLevel,
			strings.Join(r.MissingHeaders, ";"),
			strconv.FormatInt(r.DurationMs, 10),
			notAfter,
		})
	}
	return nil
}

func saveCSVPorts(path string, data []PortResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"host", "port", "open", "duration_ms", "error"})
	for _, p := range data {
		_ = w.Write([]string{
			p.Host,
			strconv.Itoa(p.Port),
			strconv.FormatBool(p.Open),
			strconv.FormatInt(p.Duration, 10),
			p.Error,
		})
	}
	return nil
}

// pretty color output
func printPrettyHeaders(results []HeaderResult) {
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	fmt.Println("\n==================== GoSec-Pro RESULTS ====================")
	for _, r := range results {
		if r.Error != "" {
			fmt.Printf("%s  %s\n", red("ERROR"), color.RedString("%s : %s", r.URL, r.Error))
			continue
		}
		levelColor := green
		if r.RiskLevel == "Moderate" {
			levelColor = yellow
		} else if r.RiskLevel == "High Risk" {
			levelColor = red
		}
		fmt.Printf("\n%s %s\n", cyan("URL:"), r.URL)
		fmt.Printf("  Status     : %s\n", r.Status)
		fmt.Printf("  Risk Score : %s (%d/100)\n", levelColor(r.RiskLevel), r.RiskScore)
		if len(r.MissingHeaders) == 0 {
			fmt.Printf("  Headers    : %s\n", green("All essential headers present ✅"))
		} else {
			fmt.Printf("  Missing    : %s\n", yellow(strings.Join(r.MissingHeaders, ", ")))
		}
		if r.TLS != nil {
			expiryNote := ""
			if r.TLS.DaysUntilExpiry <= 30 {
				expiryNote = " (expiring soon!)"
			}
			fmt.Printf("  TLS        : issuer=%s, subject=%s, expires=%s%s, tls=%s\n", r.TLS.CertIssuer, r.TLS.CertSubject, r.TLS.NotAfter, expiryNote, r.TLS.TLSVersion)
		}
		fmt.Printf("  Duration   : %d ms\n", r.DurationMs)
	}
	fmt.Println("\n============================================================")
}

func printPrettyPorts(results []PortResult) {
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	fmt.Println("\n==================== Port Scan ====================")
	for _, p := range results {
		if p.Open {
			fmt.Printf("%s:%d -> %s (%.0f ms)\n", p.Host, p.Port, green("open"), float64(p.Duration))
		} else {
			fmt.Printf("%s:%d -> %s (%.0f ms)\n", p.Host, p.Port, red("closed"), float64(p.Duration))
		}
	}
	fmt.Println("===================================================")
}

// === workflow generator ===
func generateWorkflow(path string) error {
	yaml := `name: GoSec-Pro Scan

on:
  push:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.20'
      - name: Run GoSec-Pro (scan example)
        run: |
          go run ./gosec-pro.go scan -input urls.txt -concurrency 5 -json -output results.json
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: gosec-results
          path: results.json
`
	return os.WriteFile(path, []byte(yaml), 0644)
}

// === CLI entry & flag parsing for subcommands ===
func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: gosec-pro <command> [flags]\ncommands: scan | ports | all | gen-workflow")
		return
	}

	switch os.Args[1] {
	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		urlFlag := scanCmd.String("url", "", "Single URL to scan")
		input := scanCmd.String("input", "", "File with URLs (one per line)")
		concurrency := scanCmd.Int("concurrency", 5, "Concurrent workers")
		timeout := scanCmd.Int("timeout", 10, "HTTP/TLS timeout seconds")
		retries := scanCmd.Int("retries", 0, "Retries for HTTP requests")
		delayMs := scanCmd.Int("delayms", 0, "Delay per worker in ms (rate limit)")
		jsonOut := scanCmd.Bool("json", false, "Print JSON to stdout")
		csvOut := scanCmd.Bool("csv", false, "Save CSV (requires -output)")
		output := scanCmd.String("output", "", "Write output file (JSON by default or CSV if -csv)")
		scanCmd.Parse(os.Args[2:])

		var results []HeaderResult
		if *input != "" {
			out, err := scanFromFile(*input, *concurrency, *timeout, *retries, *delayMs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
				os.Exit(1)
			}
			results = out
		} else if *urlFlag != "" {
			results = []HeaderResult{scanURL(*urlFlag, *timeout, *retries)}
		} else {
			fmt.Fprintln(os.Stderr, "scan: require -url or -input")
			scanCmd.Usage()
			return
		}

		if *jsonOut {
			b, _ := json.MarshalIndent(results, "", "  ")
			fmt.Println(string(b))
		}
		printPrettyHeaders(results)
		if *output != "" {
			if *csvOut {
				if err := saveCSVHeaders(*output, results); err != nil {
					fmt.Fprintf(os.Stderr, "failed write csv: %v\n", err)
				} else {
					fmt.Printf("Saved CSV to %s\n", *output)
				}
			} else {
				if err := saveJSON(*output, results); err != nil {
					fmt.Fprintf(os.Stderr, "failed write json: %v\n", err)
				} else {
					fmt.Printf("Saved JSON to %s\n", *output)
				}
			}
		}
	case "ports":
		portCmd := flag.NewFlagSet("ports", flag.ExitOnError)
		host := portCmd.String("host", "", "Host for port scan (required)")
		portsArg := portCmd.String("ports", "", "Comma-separated ports or ranges (e.g. 22,80,8000-8010)")
		concurrency := portCmd.Int("concurrency", 50, "Workers")
		timeoutMs := portCmd.Int("timeoutms", 200, "Dial timeout ms")
		jsonOut := portCmd.Bool("json", false, "Print JSON")
		output := portCmd.String("output", "", "Write output file (JSON)")
		portCmd.Parse(os.Args[2:])
		if *host == "" {
			fmt.Fprintln(os.Stderr, "ports: -host is required")
			portCmd.Usage()
			return
		}
		ports, err := parsePorts(*portsArg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid ports: %v\n", err)
			return
		}
		out, err := scanPorts(*host, ports, *concurrency, *timeoutMs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "port scan failed: %v\n", err)
			return
		}
		if *jsonOut {
			b, _ := json.MarshalIndent(out, "", "  ")
			fmt.Println(string(b))
		}
		printPrettyPorts(out)
		if *output != "" {
			if err := saveJSON(*output, out); err != nil {
				fmt.Fprintf(os.Stderr, "failed write json: %v\n", err)
			} else {
				fmt.Printf("Saved JSON to %s\n", *output)
			}
		}
	case "all":
		allCmd := flag.NewFlagSet("all", flag.ExitOnError)
		input := allCmd.String("input", "", "File with URLs (required)")
		portsArg := allCmd.String("ports", "", "Ports to scan for each host (comma/range)")
		concurrency := allCmd.Int("concurrency", 8, "Workers for header scans")
		portConcurrency := allCmd.Int("port-concurrency", 50, "Workers for port scans")
		timeout := allCmd.Int("timeout", 10, "HTTP/TLS timeout")
		retries := allCmd.Int("retries", 0, "HTTP retries")
		delayMs := allCmd.Int("delayms", 0, "Per-worker delay ms")
		timeoutMs := allCmd.Int("timeoutms", 200, "Port dial timeout ms")
		output := allCmd.String("output", "report.json", "Save combined report JSON")
		allCmd.Parse(os.Args[2:])

		if *input == "" {
			fmt.Fprintln(os.Stderr, "all: -input required")
			allCmd.Usage()
			return
		}
		headers, err := scanFromFile(*input, *concurrency, *timeout, *retries, *delayMs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			return
		}
		portsList, _ := parsePorts(*portsArg)
		var allPorts []PortResult
		doneHosts := map[string]bool{}
		for _, h := range headers {
			u, err := url.Parse(h.URL)
			if err != nil {
				continue
			}
			host := u.Hostname()
			if host == "" || doneHosts[host] || len(portsList) == 0 {
				continue
			}
			pr, _ := scanPorts(host, portsList, *portConcurrency, *timeoutMs)
			allPorts = append(allPorts, pr...)
			doneHosts[host] = true
		}
		combined := CombinedReport{Headers: headers, Ports: allPorts}
		if err := saveJSON(*output, combined); err != nil {
			fmt.Fprintf(os.Stderr, "failed write combined json: %v\n", err)
		} else {
			fmt.Printf("Saved combined report to %s\n", *output)
		}
		printPrettyHeaders(headers)
		printPrettyPorts(allPorts)
	case "gen-workflow":
		gen := flag.NewFlagSet("gen-workflow", flag.ExitOnError)
		out := gen.String("out", ".github/workflows/gosec-pro.yml", "Path to write workflow YAML")
		gen.Parse(os.Args[2:])
		if err := generateWorkflow(*out); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write workflow: %v\n", err)
			return
		}
		fmt.Printf("Wrote workflow to %s\n", *out)
	default:
		fmt.Println("unknown command:", os.Args[1])
		fmt.Println("usage: gosec-pro <command> [flags]\ncommands: scan | ports | all | gen-workflow")
	}
}
