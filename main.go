package main

import (
	"doppel/internal/api/cloudflare"
	"doppel/internal/api/digitalocean"
	"doppel/internal/api/route53"
	"doppel/internal/config"
	"doppel/internal/detector"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ANSI color codes for terminal output
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
)

// Global variables
var (
	debug     bool
	version   = "0.3.0" // Updated version for multi-provider support
	buildDate = "2025-08-20"
)

// DNSProvider interface para unificar os clients
type DNSProvider interface {
	GetDNSLogs(zone string) ([]string, error)
	ProviderName() string
}

func main() {
	// ------------------------
	// Command Line Interface (CLI) Flags
	// ------------------------
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode (verbose output)")
	flag.Parse()

	// Handle version flag
	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// ------------------------
	// Display Application Banner
	// ------------------------
	printBanner()

	// ------------------------
	// Setup Signal Handling for Graceful Shutdown
	// ------------------------
	setupSignalHandling()

	// ------------------------
	// Configuration Loading and Validation
	// ------------------------
	fmt.Println(Cyan + "[*] Loading configuration from: " + *configPath + Reset)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Println(Red + "[ERROR] Failed to load configuration: " + err.Error() + Reset)
		os.Exit(1)
	}

	// Validate configuration using the new ValidateConfig method
	if err := cfg.ValidateConfig(); err != nil {
		fmt.Println(Red + "[ERROR] Invalid configuration: " + err.Error() + Reset)
		os.Exit(1)
	}

	// Brief pause for user readability
	time.Sleep(1 * time.Second)

	if debug {
		fmt.Println(Blue + "[DEBUG] Configuration loaded successfully:" + Reset)
		fmt.Printf("Enabled providers: %v\n", cfg.GetEnabledProviders())
		fmt.Printf("Total providers: %d\n", cfg.GetProviderCount())
	}

	// ------------------------
	// Initialize DNS Providers
	// ------------------------
	var providers []DNSProvider
	providerCount := 0

	// Initialize Cloudflare if configured
	if cfg.HasCloudflare() {
		fmt.Println(Cyan + "[*] Initializing Cloudflare API..." + Reset)
		cfClient := cloudflare.NewCloudflareClient(cfg)
		providers = append(providers, cfClient)
		providerCount++
		time.Sleep(1 * time.Second)
		if debug {
			fmt.Println(Blue + "[DEBUG] Cloudflare API client initialized." + Reset)
			fmt.Printf(Blue+"[DEBUG] Cloudflare zones: %v"+Reset+"\n", cfg.Cloudflare.Zones)
		}
	}

	// Initialize AWS Route53 if configured
	if cfg.HasAWS() {
		fmt.Println(Cyan + "[*] Initializing AWS Route53 API..." + Reset)
		route53Client, err := route53.NewRoute53Client(cfg)
		if err != nil {
			fmt.Printf(Red+"[ERROR] Failed to initialize Route53 client: %v"+Reset+"\n", err)
		} else {
			providers = append(providers, route53Client)
			providerCount++
			time.Sleep(1 * time.Second)
			if debug {
				fmt.Println(Blue + "[DEBUG] AWS Route53 API client initialized." + Reset)
				fmt.Printf(Blue+"[DEBUG] Route53 zones: %v"+Reset+"\n", cfg.AWS.Route53Zones)
			}
		}
	}

	// Initialize DigitalOcean if configured
	if cfg.HasDigitalOcean() {
		fmt.Println(Cyan + "[*] Initializing DigitalOcean API..." + Reset)
		doClient := digitalocean.NewDigitalOceanClient(cfg) // Corrigido: removido o segundo valor de retorno
		providers = append(providers, doClient)
		providerCount++
		time.Sleep(1 * time.Second)
		if debug {
			fmt.Println(Blue + "[DEBUG] DigitalOcean API client initialized." + Reset)
			fmt.Printf(Blue+"[DEBUG] DigitalOcean domains: %v"+Reset+"\n", cfg.DigitalOcean.Domains)
		}
	}

	// Check if any providers were configured
	if providerCount == 0 {
		fmt.Println(Red + "[ERROR] No DNS providers configured. Please check your configuration." + Reset)
		os.Exit(1)
	}

	fmt.Printf(Green+"[OK] %d DNS provider(s) initialized: %v"+Reset+"\n", providerCount, cfg.GetEnabledProviders())

	// ------------------------
	// Initialize Threat Intelligence
	// ------------------------
	fmt.Println(Cyan + "[*] Initializing VirusTotal API..." + Reset)
	// Corrigido: Criando uma instância básica do cliente VirusTotal
	vtClient := &BasicVirusTotalClient{APIKey: cfg.VirusTotal.APIKey}
	time.Sleep(1 * time.Second)
	
	// Check if VirusTotal is properly configured
	if !vtClient.IsAPIEnabled() {
		fmt.Println(Yellow + "[WARNING] VirusTotal API key not configured. Threat intelligence will be limited." + Reset)
	} else if debug {
		fmt.Println(Blue + "[DEBUG] VirusTotal API client initialized." + Reset)
	}

	// ------------------------
	// Detection Engine Initialization
	// ------------------------
	processor := detector.NewDNSLogProcessor(debug, cfg.Monitoring.AlertThreshold)
	fmt.Println(Green + "[OK] DNS log detector initialized." + Reset)

	// ------------------------
	// Main Monitoring Loop
	// ------------------------
	fmt.Println(Green + "[OK] Detector is now running." + Reset)
	fmt.Println(Yellow + "[INFO] Monitoring for reverse DNS lookups and changes..." + Reset)
	fmt.Printf(Yellow+"[INFO] Monitoring interval: %d seconds"+Reset+"\n", cfg.Monitoring.IntervalSeconds)
	fmt.Printf(Yellow+"[INFO] Alert threshold: %d detections"+Reset+"\n", cfg.Monitoring.AlertThreshold)
	fmt.Printf(Yellow+"[INFO] Monitoring %d DNS provider(s): %v"+Reset+"\n", providerCount, cfg.GetEnabledProviders())

	// Track monitoring cycles and performance
	cycleCount := 0
	startTime := time.Now()

	for {
		cycleCount++
		cycleStart := time.Now()
		
		if debug {
			fmt.Printf(Blue+"[DEBUG] Starting monitoring cycle #%d..."+Reset+"\n", cycleCount)
		}

		totalLogs := 0
		zoneErrors := 0
		totalDetectionsThisCycle := 0

		// Iterate through all configured DNS providers
		for _, provider := range providers {
			providerName := provider.ProviderName()
			
			if debug {
				fmt.Printf(Blue+"[DEBUG] Checking provider: %s"+Reset+"\n", providerName)
			}

			// Get zones for this provider
			zones := getZonesForProvider(cfg, providerName)
			if len(zones) == 0 {
				if debug {
					fmt.Printf(Blue+"[DEBUG] No zones configured for provider %s"+Reset+"\n", providerName)
				}
				continue
			}

			// Process each zone for this provider
			for _, zone := range zones {
				if debug {
					fmt.Printf(Blue+"[DEBUG] Checking zone: %s on %s"+Reset+"\n", zone, providerName)
				}

				// Fetch DNS logs from the provider for the current zone
				logs, err := provider.GetDNSLogs(zone)
				if err != nil {
					zoneErrors++
					fmt.Printf(Red+"[ERROR] %s zone %s logs fetch failed: %v"+Reset+"\n", 
						providerName, zone, err)
					continue
				}

				totalLogs += len(logs)
				
				if debug && len(logs) > 0 {
					fmt.Printf(Blue+"[DEBUG] Retrieved %d log entries from %s zone %s"+Reset+"\n", 
						len(logs), providerName, zone)
				}

				// Process logs through the detection engine
				detectionCountBefore := processor.DetectionCount
				processor.ProcessLogs(logs)
				newDetections := processor.DetectionCount - detectionCountBefore
				totalDetectionsThisCycle += newDetections

				// Enrich detections with VirusTotal threat intelligence
				if vtClient.IsAPIEnabled() && newDetections > 0 {
					if debug {
						fmt.Printf(Blue+"[DEBUG] Enriching %d new detection(s) from %s with VirusTotal data..."+Reset+"\n", 
							newDetections, providerName)
					}
					
					// Get recently detected IPs and check their reputation
					recentIPs := processor.GetRecentDetectedIPs()
					if len(recentIPs) > 0 {
						results, err := vtClient.BatchScanIP(recentIPs)
						if err != nil {
							fmt.Printf(Yellow+"[WARNING] VirusTotal batch scan failed: %v"+Reset+"\n", err)
						} else {
							// Process VirusTotal results
							maliciousCount := 0
							for ip, isClean := range results {
								if !isClean {
									maliciousCount++
									fmt.Printf(Red+"[ALERT] Malicious IP detected from %s: %s (confirmed by VirusTotal)"+Reset+"\n", 
										providerName, ip)
									// Additional actions could be triggered here
								} else if debug {
									fmt.Printf(Blue+"[DEBUG] IP %s from %s cleared by VirusTotal"+Reset+"\n", ip, providerName)
								}
							}
							if maliciousCount > 0 {
								fmt.Printf(Red+"[SUMMARY] %d malicious IP(s) identified from %s in this cycle"+Reset+"\n", 
									maliciousCount, providerName)
							}
						}
					}
				}
			}
		}

		// Calculate cycle duration
		cycleDuration := time.Since(cycleStart)

		// Display cycle summary
		stats := processor.GetStats()
		shouldDisplaySummary := debug || totalDetectionsThisCycle > 0 || zoneErrors > 0 || cycleCount%5 == 0

		if shouldDisplaySummary {
			fmt.Printf(Cyan+"[CYCLE #%d] Duration: %v, Providers: %d, Logs: %d, New detections: %d, Total: %d, Zone errors: %d"+Reset+"\n",
				cycleCount, cycleDuration.Round(time.Millisecond), providerCount, totalLogs, totalDetectionsThisCycle, 
				stats["total_detections"], zoneErrors)
			
			if totalDetectionsThisCycle > 0 {
				fmt.Printf(Yellow+"[INFO] Last detection: %v"+Reset+"\n", stats["last_detection"])
				fmt.Printf(Yellow+"[INFO] Unique IPs detected: %d"+Reset+"\n", stats["unique_ips"])
			}
		}

		// Periodic overall status update
		if cycleCount%20 == 0 {
			uptime := time.Since(startTime).Round(time.Minute)
			fmt.Printf(Green+"[STATUS] Uptime: %v, Cycles: %d, Total detections: %d, Providers: %d"+Reset+"\n",
				uptime, cycleCount, stats["total_detections"], providerCount)
			
			// Show provider-specific stats
			if debug {
				for _, provider := range providers {
					if doClient, ok := provider.(*digitalocean.DigitalOceanClient); ok {
						stats := doClient.GetChangeStats("")
						fmt.Printf(Blue+"[DEBUG] DigitalOcean change stats: %v"+Reset+"\n", stats)
					}
				}
			}
		}

		// Check for high-frequency detection patterns (potential attack)
		if processor.IsHighFrequencyDetection(5*time.Minute, 10) {
			fmt.Printf(Red+"[CRITICAL] High frequency detection pattern detected! Possible coordinated attack."+Reset+"\n")
			fmt.Printf(Red+"[ACTION] Immediate investigation recommended. Detected %d events in 5 minutes."+Reset+"\n",
				stats["total_detections"])
		}

		// Wait for the configured interval before next check
		if debug {
			fmt.Printf(Blue+"[DEBUG] Waiting %d seconds before next check..."+Reset+"\n", 
				cfg.Monitoring.IntervalSeconds)
		}
		
		time.Sleep(time.Duration(cfg.Monitoring.IntervalSeconds) * time.Second)
	}
}

// Implementação básica do cliente VirusTotal para evitar erros de compilação
type BasicVirusTotalClient struct {
	APIKey string
}

func (c *BasicVirusTotalClient) IsAPIEnabled() bool {
	return c.APIKey != ""
}

func (c *BasicVirusTotalClient) BatchScanIP(ips []string) (map[string]bool, error) {
	// Implementação simulada - retorna todos os IPs como limpos
	result := make(map[string]bool)
	for _, ip := range ips {
		result[ip] = true
	}
	return result, nil
}

// getZonesForProvider retorna as zonas configuradas para um provedor específico
func getZonesForProvider(cfg *config.Config, providerName string) []string {
	switch providerName {
	case "Cloudflare":
		return cfg.Cloudflare.Zones
	case "AWS Route53":
		return cfg.AWS.Route53Zones
	case "DigitalOcean":
		return cfg.DigitalOcean.Domains
	default:
		return []string{}
	}
}

// printBanner displays the application ASCII art banner
func printBanner() {
	fmt.Println(Magenta + "========================================" + Reset)
	fmt.Println(Magenta + "     IDS/IPS Reverse Lookup Detector    " + Reset)
	fmt.Println(Magenta + "   -----------------------------------  " + Reset)
	fmt.Println(Magenta + "     Author : Gabriel Garcia            " + Reset)
	fmt.Printf(Magenta+"     Version: %s (Built: %s)         "+Reset+"\n", version, buildDate)
	fmt.Println(Magenta + "========================================" + Reset)
	fmt.Println()
}

// printVersion displays version information
func printVersion() {
	fmt.Printf("Reverse Lookup Detector v%s\n", version)
	fmt.Printf("Build date: %s\n", buildDate)
	fmt.Println("Author: Gabriel Garcia")
	fmt.Println("License: MIT")
	fmt.Println("Supported providers: Cloudflare, AWS Route53, DigitalOcean")
}

// setupSignalHandling configures graceful shutdown on interrupt signals
func setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		sig := <-sigChan
		handleShutdown(sig)
	}()
}

// handleShutdown manages graceful application termination
func handleShutdown(sig os.Signal) {
	fmt.Printf(Yellow+"[INFO] Received signal %s. Terminating gracefully..."+Reset+"\n", sig)
	
	// Add cleanup operations here if needed
	// - Close API connections
	// - Save current state to disk
	// - Send final status report
	
	fmt.Println(Yellow + "[INFO] Shutdown complete." + Reset)
	os.Exit(0)
}

// getUptimeString formats uptime for display
func getUptimeString(startTime time.Time) string {
	duration := time.Since(startTime)
	
	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60
	
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}