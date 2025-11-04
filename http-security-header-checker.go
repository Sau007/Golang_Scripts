// Simple HTTP Security Header Checker //

package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var requiredHeaders = []string{
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"Referrer-Policy",
	"Permissions-Policy",
}

func checkURL(raw string) error {
	// Basic validation
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	// set a common user-agent
	req.Header.Set("User-Agent", "Ghost-Security-Checker/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("URL: %s\n", u.String())
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Println("-- Security headers report --")

	found := map[string]string{}
	for k, v := range resp.Header {
		found[k] = strings.Join(v, "; ")
	}

	for _, h := range requiredHeaders {
		if val, ok := found[h]; ok {
			fmt.Printf("[OK]    %-25s : %s\n", h, val)
		} else {
			fmt.Printf("[MISSING] %-21s : NOT PRESENT\n", h)
		}
	}

	// Quick additional checks
	if resp.TLS == nil && u.Scheme == "https" {
		fmt.Println("[WARN] Response has no TLS info (server may be redirecting or using insecure transport)")
	}

	// report cookies flagged as insecure/samesite
	for _, c := range resp.Cookies() {
		var sameSite string
		switch c.SameSite {
		case http.SameSiteDefaultMode:
			sameSite = "Default"
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteNoneMode:
			sameSite = "None"
		default:
			sameSite = "Unknown"
		}

		insecure := ""
		if !c.Secure {
			insecure = " [not Secure]"
		}
		fmt.Printf("Cookie: %-20s ; Path=%s ; SameSite=%s%s\n", c.Name, c.Path, sameSite, insecure)
	}

	return nil
}

func main() {
	var rawurl string
	flag.StringVar(&rawurl, "url", "", "Target URL to check (include scheme, e.g. https://example.com)")
	flag.Parse()

	if rawurl == "" {
		fmt.Fprintln(os.Stderr, "Error: -url is required\nUsage: go run http-security-header-checker.go -url https://example.com")
		os.Exit(2)
	}

	if err := checkURL(rawurl); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Usage: go run http-security-header-checker.go -url https://example.com //

