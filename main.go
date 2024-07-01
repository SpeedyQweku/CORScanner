package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

type CORSConfig struct {
	AllowOrigins     []string `json:"allowOrigins"`
	AllowMethods     []string `json:"allowMethods"`
	AllowHeaders     []string `json:"allowHeaders"`
	ExposeHeaders    []string `json:"exposeHeaders"`
	MaxAge           int      `json:"maxAge"`
	AllowCredentials string   `json:"allowCredentials"`
}

type CORSResult struct {
	URL           string     `json:"url"`
	StatusCode    int        `json:"statusCode"`
	CORSConfig    CORSConfig `json:"corsConfig"`
	Vulnerable    bool       `json:"vulnerable"`
	Vulnerability string     `json:"vulnerability"`
}

func parseHeader(header string) []string {
	if header == "" {
		return []string{}
	}
	return strings.Split(header, ",")
}

func checkCORS(url string, results chan CORSResult) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		// fmt.Printf("Error creating request for URL %s: %v\n", url, err)
		return
	}

	fmt.Printf("[>] Making request to URL: %s\n", url)
	req.Header.Set("Origin", "null")
	resp, err := client.Do(req)
	if err != nil {
		// fmt.Printf("Error making request to URL %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	corsConfig := CORSConfig{}
	corsConfig.AllowOrigins = []string{resp.Header.Get("Access-Control-Allow-Origin")}
	corsConfig.AllowMethods = parseHeader(resp.Header.Get("Access-Control-Allow-Methods"))
	corsConfig.AllowHeaders = parseHeader(resp.Header.Get("Access-Control-Allow-Headers"))
	corsConfig.ExposeHeaders = parseHeader(resp.Header.Get("Access-Control-Expose-Headers"))
	corsConfig.MaxAge, _ = strconv.Atoi(resp.Header.Get("Access-Control-Max-Age"))
	corsConfig.AllowCredentials = resp.Header.Get("Access-Control-Allow-Credentials")

	vulnerable := false
	vulnerability := ""

	if corsConfig.AllowOrigins[0] == "*" {
		vulnerable = true
		vulnerability = "Wildcard origin (*) is set, which can allow malicious scripts to make requests on behalf of the user."
	} else if corsConfig.AllowOrigins[0] == "null" {
		vulnerable = true
		vulnerability = "Null origin is allowed, which can allow malicious scripts to make requests on behalf of the user."
	} else {
		eTLD, _ := publicsuffix.PublicSuffix(url)
		if eTLD != "" && strings.HasSuffix(corsConfig.AllowOrigins[0], eTLD) {
			vulnerable = true
			vulnerability = "Origin allows the same domain as the target URL, which can allow malicious scripts to make requests on behalf of the user."
		}
	}

	if !vulnerable {
		// Try with a different origin if the initial check doesn't find any vulnerabilities
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			// fmt.Printf("Error creating request for URL %s: %v\n", url, err)
			return
		}

		req.Header.Set("Origin", "http://example.com")
		resp, err = client.Do(req)
		if err != nil {
			// fmt.Printf("Error making request to URL %s: %v\n", url, err)
			return
		}
		defer resp.Body.Close()

		corsConfig.AllowOrigins = []string{resp.Header.Get("Access-Control-Allow-Origin")}
		corsConfig.AllowMethods = parseHeader(resp.Header.Get("Access-Control-Allow-Methods"))
		corsConfig.AllowHeaders = parseHeader(resp.Header.Get("Access-Control-Allow-Headers"))
		corsConfig.ExposeHeaders = parseHeader(resp.Header.Get("Access-Control-Expose-Headers"))
		corsConfig.MaxAge, _ = strconv.Atoi(resp.Header.Get("Access-Control-Max-Age"))
		corsConfig.AllowCredentials = resp.Header.Get("Access-Control-Allow-Credentials")

		if corsConfig.AllowOrigins[0] == "http://example.com" {
			vulnerable = true
			vulnerability = "Origin allows a different domain, which can allow malicious scripts to make requests on behalf of the user."
		}
	}

	if !vulnerable {
		// Try with the domain origin if the previous checks don't find any vulnerabilities
		u, err := neturl.Parse(url)
		if err != nil {
			// fmt.Printf("Error parsing URL %s: %v\n", url, err)
			return
		}

		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			// fmt.Printf("Error creating request for URL %s: %v\n", url, err)
			return
		}

		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
		resp, err = client.Do(req)
		if err != nil {
			// fmt.Printf("Error making request to URL %s: %v\n", url, err)
			return
		}
		defer resp.Body.Close()

		corsConfig.AllowOrigins = []string{resp.Header.Get("Access-Control-Allow-Origin")}
		corsConfig.AllowMethods = parseHeader(resp.Header.Get("Access-Control-Allow-Methods"))
		corsConfig.AllowHeaders = parseHeader(resp.Header.Get("Access-Control-Allow-Headers"))
		corsConfig.ExposeHeaders = parseHeader(resp.Header.Get("Access-Control-Expose-Headers"))
		corsConfig.MaxAge, _ = strconv.Atoi(resp.Header.Get("Access-Control-Max-Age"))
		corsConfig.AllowCredentials = resp.Header.Get("Access-Control-Allow-Credentials")

		if corsConfig.AllowOrigins[0] == u.Scheme+"://"+u.Host {
			vulnerable = true
			vulnerability = "Origin allows the same domain as the target URL, which can allow malicious scripts to make requests on behalf of the user."
		}
	}

	result := CORSResult{
		URL:           url,
		StatusCode:    resp.StatusCode,
		CORSConfig:    corsConfig,
		Vulnerable:    vulnerable,
		Vulnerability: vulnerability,
	}

	if vulnerable {
		results <- result
	}
}

func writeResultsToFile(filename string, results []CORSResult) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file %s: %v\n", filename, err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	_, _ = file.WriteString("[\n")
	for i, result := range results {
		if err := encoder.Encode(result); err != nil {
			fmt.Printf("Error encoding result: %v\n", err)
			continue
		}
		if i < len(results)-1 {
			_, _ = file.WriteString(",\n")
		}
	}
	_, _ = file.WriteString("]\n")
}

func main() {
	// Define command-line flags
	filePath := flag.String("f", "", "Path to the file containing URLs")
	concurrency := flag.Int("c", 70, "Number of concurrent workers")
	flag.Parse()

	// Check if file path is provided
	if *filePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	urls, err := ioutil.ReadFile(*filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	urlList := strings.Split(strings.TrimSpace(string(urls)), "\n")

	var wg sync.WaitGroup
	results := make(chan CORSResult, len(urlList))
	urlChan := make(chan string, len(urlList))

	// Start workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				if url != "" {
					checkCORS(url, results)
				}
			}
		}()
	}

	// Distribute URLs to workers
	go func() {
		for _, url := range urlList {
			urlChan <- url
		}
		close(urlChan)
	}()

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and categorize them
	nullOriginResults := []CORSResult{}
	wildcardOriginResults := []CORSResult{}
	domainOriginResults := []CORSResult{}
	differentDomainResults := []CORSResult{}

	for result := range results {
		switch {
		case strings.Contains(result.Vulnerability, "Null origin"):
			nullOriginResults = append(nullOriginResults, result)
		case strings.Contains(result.Vulnerability, "Wildcard origin"):
			wildcardOriginResults = append(wildcardOriginResults, result)
		case strings.Contains(result.Vulnerability, "same domain"):
			domainOriginResults = append(domainOriginResults, result)
		case strings.Contains(result.Vulnerability, "different domain"):
			differentDomainResults = append(differentDomainResults, result)
		}
		jsonResult, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Println("Error marshaling result:", err)
			continue
		}
		fmt.Println(string(jsonResult))
	}

	// Write results to files
	writeResultsToFile("null_origin_vulnerabilities.json", nullOriginResults)
	writeResultsToFile("wildcard_origin_vulnerabilities.json", wildcardOriginResults)
	writeResultsToFile("domain_origin_vulnerabilities.json", domainOriginResults)
	writeResultsToFile("different_domain_origin_vulnerabilities.json", differentDomainResults)

	// Print the results notification
	fmt.Println("\n[-] Results are saved in 4 files:")
	fmt.Println("\tnull_origin_vulnerabilities.json")
	fmt.Println("\twildcard_origin_vulnerabilities.json")
	fmt.Println("\tdomain_origin_vulnerabilities.json")
	fmt.Println("\tdifferent_domain_origin_vulnerabilities.json")
}
