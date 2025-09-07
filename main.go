package main

import (
	"bufio"
	"context"
	"bytes"
	"doppel/internal/api"
	"doppel/internal/config"
	"doppel/internal/detector"
	"doppel/internal/dohserver"
	"encoding/json"
	"net/http"
	"flag"
	"fmt"
	"io"
	"os"
	"log"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/joho/godotenv"
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

var (
	debug       bool
	enableDoh   bool // Nova flag para habilitar servidor DoH
	version     = "0.3.1"
	buildDate   = "2025-08-24"
) 

func init() {
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found")
    }
}

func main() {
	// ------------------------
	// CLI Flags
	// ------------------------
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode (verbose output)")
	flag.BoolVar(&enableDoh, "doh", false, "Enable DoH fake server")
	flag.Parse()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	printBanner()
	setupSignalHandling()

	// ------------------------
	// Load Config
	// ------------------------
	fmt.Println(Cyan + "[*] Loading configuration from: " + *configPath + Reset)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Println(Red + "[ERROR] Failed to load configuration: " + err.Error() + Reset)
		os.Exit(1)
	}
	if err := cfg.ValidateConfig(); err != nil {
		fmt.Println(Red + "[ERROR] Invalid configuration: " + err.Error() + Reset)
		os.Exit(1)
	}
	time.Sleep(300 * time.Millisecond)
	if debug {
		fmt.Println(Blue + "[DEBUG] Configuration loaded successfully:" + Reset)
		fmt.Printf("Enabled providers: %v\n", cfg.GetEnabledProviders())
		fmt.Printf("Total providers: %d\n", cfg.GetProviderCount())
		if cfg.HasDocker() {
			fmt.Printf(Blue+"[DEBUG] Docker: container=%s, stdlogs=%v, tail_files=%v, files=%v"+Reset+"\n",
				cfg.DockerContainer(), cfg.DockerReadStdLogs(), cfg.DockerTailFiles(), cfg.DockerFiles())
		}
	}

	// ------------------------
	// Detection Engine
	// ------------------------
	processor := detector.NewDNSLogProcessor(debug, cfg.Monitoring.AlertThreshold)
	fmt.Println(Green + "[OK] DNS log detector initialized." + Reset)

	// ------------------------
	// Docker log capture (stdout/stderr e/ou files)
	// ------------------------
	hasLocalInputs := false
	if cfg.HasDocker() {
		cont := cfg.DockerContainer()
		hasLocalInputs = true
		fmt.Printf(Cyan+"[*] Docker log capture enabled for container: %s"+Reset+"\n", cont)

		if cfg.DockerReadStdLogs() {
			go streamDockerStdLogsWithReconnect(cont, processor)
		}
		if cfg.DockerTailFiles() {
			files := cfg.DockerFiles()
			go tailFilesInsideContainer(cont, files, processor)
		}
	}

	// ------------------------
	// DNS Providers (opcional, ex.: Route53)
	// ------------------------
	var providers []api.DNSProvider
	providerCount := 0

	if cfg.HasAWS() {
		fmt.Println(Cyan + "[*] Initializing AWS Route53 API (CloudWatch)..." + Reset)
		route53Client, err := api.NewRoute53Client(cfg)
		if err != nil {
			fmt.Printf(Red+"[ERROR] Failed to initialize Route53 client: %v"+Reset+"\n", err)
		} else {
			providers = append(providers, route53Client)
			providerCount++
			if debug {
				fmt.Println(Blue + "[DEBUG] AWS Route53 client initialized." + Reset)
				fmt.Printf(Blue+"[DEBUG] Route53 zones (hosted zone IDs): %v"+Reset+"\n", cfg.AWS.Route53Zones)
			}
		}
	}

	// Se não houver provider e também não houver entradas locais (docker), erro.
	if providerCount == 0 && !hasLocalInputs {
		fmt.Println(Red + "[ERROR] No DNS providers or local docker inputs configured. Enable Route53 or Docker capture in config.yaml." + Reset)
		os.Exit(1)
	}
	fmt.Printf(Green+"[OK] %d DNS provider(s) initialized: %v"+Reset+"\n", providerCount, cfg.GetEnabledProviders())

	// ------------------------
	// Threat Intel (VirusTotal)
	// ------------------------
	//fmt.Println(Cyan + "[*] Initializing VirusTotal API..." + Reset)
	//vtClient := api.NewVirusTotalClient(cfg)
	//if !vtClient.IsAPIEnabled() {
	//	fmt.Println(Yellow + "[WARNING] VirusTotal API key not configured. Threat intelligence will be limited." + Reset)
	//} else if debug {
	//	fmt.Println(Blue + "[DEBUG] VirusTotal API client initialized." + Reset)
	//}

	// ------------------------
	// Start DoH Fake Server (optional - habilitado por flag)
	// ------------------------
	if enableDoh {
    	fmt.Println(Cyan + "[*] Starting DoH fake server (enabled by -doh flag)..." + Reset)
    
 		// Configuração padrão (você pode ajustar esses valores)
    	dohPort := 443
    	dohCertFile := ""
    	dohKeyFile := ""
    	dohDomain := "localhost"
    	dohUseLetsEncrypt := false
    	dohRealisticDelay := true
    
    	dohServer := dohserver.NewDoHServer(
        	processor,
        	dohPort,
        	dohCertFile,
        	dohKeyFile,
        	dohDomain,
        	debug,
        	dohUseLetsEncrypt,
        	dohRealisticDelay,
    	)
    
    	go func() {
        	if err := dohServer.Start(); err != nil {
            	fmt.Printf(Red+"[ERROR] DoH server failed: %v"+Reset+"\n", err)
        	}
    	}()
    
    	fmt.Printf(Green+"[OK] DoH server started on port %d"+Reset+"\n", dohPort)
    	fmt.Printf(Yellow+"[INFO] DoH fake server enabled on port %d"+Reset+"\n", dohPort)
	}
		
	// ------------------------
	// Main loop
	// ------------------------
	fmt.Println(Green + "[OK] Detector is now running." + Reset)
	fmt.Println(Yellow + "[INFO] Monitoring for DNS queries (A/AAAA/PTR) and changes..." + Reset)
	fmt.Printf(Yellow+"[INFO] Monitoring interval: %d seconds"+Reset+"\n", cfg.Monitoring.IntervalSeconds)
	fmt.Printf(Yellow+"[INFO] Alert threshold: %d detections"+Reset+"\n", cfg.Monitoring.AlertThreshold)
	fmt.Printf(Yellow+"[INFO] Monitoring %d DNS provider(s): %v"+Reset+"\n", providerCount, cfg.GetEnabledProviders())
	
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

		for _, provider := range providers {
			providerName := provider.ProviderName()
			if debug {
				fmt.Printf(Blue+"[DEBUG] Checking provider: %s"+Reset+"\n", providerName)
			}

			zones := getZonesForProvider(cfg, providerName)
			if len(zones) == 0 {
				if debug {
					fmt.Printf(Blue+"[DEBUG] No zones configured for provider %s"+Reset+"\n", providerName)
				}
				continue
			}

			for _, zone := range zones {
				if debug {
					fmt.Printf(Blue+"[DEBUG] Checking zone: %s on %s"+Reset+"\n", zone, providerName)
				}
				logs, err := provider.GetDNSLogs(zone)
				if err != nil {
					zoneErrors++
					fmt.Printf(Red+"[ERROR] %s zone %s logs fetch failed: %v"+Reset+"\n", providerName, zone, err)
					continue
				}

				totalLogs += len(logs)
				if debug && len(logs) > 0 {
					fmt.Printf(Blue+"[DEBUG] Retrieved %d log entries from %s zone %s"+Reset+"\n", len(logs), providerName, zone)
				}

				before := processor.DetectionCount
				processor.ProcessLogs(logs)
				newDet := processor.DetectionCount - before
				totalDetectionsThisCycle += newDet

				// (Opcional) enriquecer novas detecções com VT
				//if vtClient.IsAPIEnabled() && newDet > 0 && debug {
				//	fmt.Printf(Blue+"[DEBUG] Enriching %d new detection(s) from %s with VirusTotal data..."+Reset+"\n", newDet, providerName)
				//}
			}
		}

		cycleDuration := time.Since(cycleStart)
		stats := processor.GetStats()
			
		if debug || totalDetectionsThisCycle > 0 || zoneErrors > 0 || cycleCount%5 == 0 {
			fmt.Printf(Cyan+"[CYCLE #%d] Duration: %v, Providers: %d, Logs: %d, New detections: %d, Total: %d, Zone errors: %d"+Reset+"\n",
				cycleCount, cycleDuration.Round(time.Millisecond), providerCount, totalLogs, totalDetectionsThisCycle,
				stats["total_detections"], zoneErrors)
		}
			
		if hits := processor.GetAndResetCycleDetections(); hits > 0 {
			fmt.Printf(Red+"[CRITICAL] Possible reconnaissance detected: %d DNS query event(s) observed since last cycle."+Reset+"\n", hits)
			fmt.Printf(Yellow+"[INFO] Unique source IPs so far: %d"+Reset+"\n", stats["unique_ips"])
			
			// Monte o resumo/detalhes para o workflow
			summary := fmt.Sprintf("Recon detected: %d DNS event(s) in last cycle", hits)
			details := fmt.Sprintf(
				"Cycle: #%d | Unique IPs: %d | Total detections: %v | Providers: %d",
				cycleCount, stats["unique_ips"], stats["total_detections"], providerCount,
			)
			
			userEmail := strings.TrimSpace(cfg.Notifications.Email.To)
			if userEmail == "" {
				fmt.Println(Yellow + "[WARNING] notifications.email.to is empty in config.yaml — skipping Lambda trigger." + Reset)
			} else {
				apiKey := os.Getenv("DOPPEL_LAMBDA_API_KEY")
				if apiKey == "" {
					fmt.Println(Yellow + "[WARNING] DOPPEL_LAMBDA_API_KEY is empty — skipping Lambda trigger." + Reset)
				} else {
					payload := map[string]string{
						"user_email": userEmail,
						"api_key":    apiKey,
						"summary":    summary,
						"details":    details,
					}
					body, _ := json.Marshal(payload)
			
					ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
					defer cancel()
			
					req, err := http.NewRequestWithContext(
						ctx,
						http.MethodPost,
						"https://pyq5ocdjhl.execute-api.us-east-1.amazonaws.com/prod/trigger",
						bytes.NewBuffer(body),
					)
					if err != nil {
						fmt.Printf(Yellow+"[WARNING] Failed to build request to Lambda: %v"+Reset+"\n", err)
					} else {
						req.Header.Set("Content-Type", "application/json")
			
						httpClient := &http.Client{Timeout: 8 * time.Second}
						resp, err := httpClient.Do(req)
						if err != nil {
							fmt.Printf(Yellow+"[WARNING] Failed to POST to Lambda: %v"+Reset+"\n", err)
						} else {
							defer resp.Body.Close()
							respBody, _ := io.ReadAll(resp.Body)
			
							if resp.StatusCode >= 200 && resp.StatusCode < 300 {
								fmt.Printf(Green+"[OK] Lambda responded (%d): %s"+Reset+"\n", resp.StatusCode, string(respBody))
							} else {
								fmt.Printf(Yellow+"[WARNING] Lambda error (%d): %s"+Reset+"\n", resp.StatusCode, string(respBody))
							}
						}
					}
				}
			}
		}				
				
		if cycleCount%20 == 0 {
			uptime := time.Since(startTime).Round(time.Minute)
			fmt.Printf(Green+"[STATUS] Uptime: %v, Cycles: %d, Total detections: %d, Providers: %d"+Reset+"\n",
				uptime, cycleCount, stats["total_detections"], providerCount)
		}

		if processor.IsHighFrequencyDetection(5*time.Minute, 10) {
			fmt.Printf(Red+"[CRITICAL] High frequency detection pattern detected! Possible coordinated attack."+Reset+"\n")
		}

		if debug {
			fmt.Printf(Blue+"[DEBUG] Waiting %d seconds before next check..."+Reset+"\n", cfg.Monitoring.IntervalSeconds)
		}
		time.Sleep(time.Duration(cfg.Monitoring.IntervalSeconds) * time.Second)
	}
}

// --------- BIND9 (host) - util opcional ---------

func monitorBIND9Logs(processor *detector.DNSLogProcessor) {
	logFiles := []string{
		filepath.Join(os.Getenv("HOME"), "bind9/logs/named.log"),
		"/var/log/bind/named.log",
		"/var/log/named.log",
	}

	fmt.Println(Cyan + "[*] Checking for available BIND9 log files..." + Reset)
	var found []string
	for _, f := range logFiles {
		if _, err := os.Stat(f); err == nil {
			found = append(found, f)
			fmt.Printf(Green+"[OK] Found log file: %s"+Reset+"\n", f)
		}
	}
	if len(found) == 0 {
		fmt.Println(Yellow + "[WARNING] No BIND9 log files found on host. BIND9 host monitoring disabled." + Reset)
		return
	}
	for _, f := range found {
		go tailLogFile(f, processor)
	}
}

func tailLogFile(path string, processor *detector.DNSLogProcessor) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf(Red+"[ERROR] Failed to open log file %s: %v"+Reset+"\n", path, err)
		return
	}
	defer file.Close()

	fmt.Printf(Cyan+"[*] Tailing log file: %s"+Reset+"\n", path)

	file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			fmt.Printf(Red+"[ERROR] Error reading log file %s: %v"+Reset+"\n", path, err)
			break
		}
		line = strings.TrimRight(line, "\r\n")
		processor.ProcessLogs([]string{line})
		if debug {
			fmt.Printf(Blue+"[DEBUG] Log line processed: %s"+Reset+"\n", line)
		}
	}
}

// --------- Docker (container) ---------

// streamDockerStdLogsWithReconnect abre o stream e reconecta caso caia.
// Também trata TTY vs não-TTY corretamente.
func streamDockerStdLogsWithReconnect(container string, processor *detector.DNSLogProcessor) {
	for {
		err := streamDockerStdLogsOnce(container, processor)
		if err != nil {
			fmt.Printf(Yellow+"[WARNING] Docker log stream ended (%v). Reconnecting in 2s..."+Reset+"\n", err)
			time.Sleep(2 * time.Second)
			continue
		}
		// terminou sem erro explícito (container parou?) — tenta reconectar mesmo assim
		time.Sleep(2 * time.Second)
	}
}

func streamDockerStdLogsOnce(container string, processor *detector.DNSLogProcessor) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		fmt.Printf(Yellow+"[WARNING] Docker client init failed: %v"+Reset+"\n", err)
		return err
	}
	ctx := context.Background()

	// Inspeciona o container para saber se TTY está habilitado.
	inspect, err := cli.ContainerInspect(ctx, container)
	if err != nil {
		fmt.Printf(Yellow+"[WARNING] ContainerInspect failed for %s: %v"+Reset+"\n", container, err)
		return err
	}
	tty := false
	if inspect.Config != nil {
		tty = inspect.Config.Tty
	}
	if debug {
		fmt.Printf(Blue+"[DEBUG] Docker inspect: running=%v, TTY=%v"+Reset+"\n", inspect.State != nil && inspect.State.Running, tty)
	}

	// Usamos Since para começar "agora - 1s"
	since := time.Now().Add(-1 * time.Second).UTC().Format(time.RFC3339)
	opts := types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Since:      since,
	}

	rdr, err := cli.ContainerLogs(ctx, container, opts)
	if err != nil {
		fmt.Printf(Yellow+"[WARNING] Unable to stream docker logs for %s: %v"+Reset+"\n", container, err)
		return err
	}
	defer rdr.Close()

	fmt.Printf(Green+"[OK] Attached to docker logs (stdout/stderr) for container: %s"+Reset+"\n", container)

	if tty {
		// TTY = stream não multiplexado → ler direto do rdr
		sc := bufio.NewScanner(rdr)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line != "" {
				processor.ProcessLogs([]string{line})
				if debug {
					fmt.Printf(Blue+"[DEBUG][docker-tty] %s"+Reset+"\n", line)
				}
			}
		}
		return sc.Err()
	}

	// NÃO TTY = stream multiplexado → demultiplex com StdCopy
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()

	// Copiador em background
	done := make(chan struct{})
	go func() {
		_, _ = stdcopy.StdCopy(stdoutW, stderrW, rdr)
		stdoutW.Close()
		stderrW.Close()
		close(done)
	}()

	// stdout
	errCh := make(chan error, 2)
	go func() {
		sc := bufio.NewScanner(stdoutR)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line != "" {
				processor.ProcessLogs([]string{line})
				if debug {
					fmt.Printf(Blue+"[DEBUG][docker-stdout] %s"+Reset+"\n", line)
				}
			}
		}
		errCh <- sc.Err()
	}()

	// stderr
	go func() {
		sc := bufio.NewScanner(stderrR)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line != "" {
				processor.ProcessLogs([]string{line})
				if debug {
					fmt.Printf(Blue+"[DEBUG][docker-stderr] %s"+Reset+"\n", line)
				}
			}
		}
		errCh <- sc.Err()
	}()

	// Espera o copiador terminar ou algum scanner retornar erro
	select {
	case <-done:
		return io.EOF
	case e1 := <-errCh:
		return e1
	}
}

func tailFilesInsideContainer(container string, files []string, processor *detector.DNSLogProcessor) {
	var cleaned []string
	for _, f := range files {
		f = strings.TrimSpace(f)
		if f != "" {
			cleaned = append(cleaned, f)
		}
	}
	if len(cleaned) == 0 {
		if debug {
			fmt.Println(Yellow + "[WARNING] No docker files provided to tail" + Reset)
		}
		return
	}

	cmd := "tail -n0 -F " + strings.Join(cleaned, " ")
	if debug {
		fmt.Printf(Blue+"[DEBUG] docker exec tail cmd: %s"+Reset+"\n", cmd)
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		fmt.Printf(Yellow+"[WARNING] Docker client init failed (tail files): %v"+Reset+"\n", err)
		return
	}
	ctx := context.Background()

	execCfg := types.ExecConfig{
		Cmd:          []string{"sh", "-lc", cmd},
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	}

	execIDResp, err := cli.ContainerExecCreate(ctx, container, execCfg)
	if err != nil {
		fmt.Printf(Yellow+"[WARNING] ContainerExecCreate failed: %v"+Reset+"\n", err)
		return
	}

	attach, err := cli.ContainerExecAttach(ctx, execIDResp.ID, types.ExecStartCheck{Tty: false})
	if err != nil {
		fmt.Printf(Yellow+"[WARNING] ContainerExecAttach failed: %v"+Reset+"\n", err)
		return
	}
	// manter vivo para seguir o -F

	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	go func() {
		_, _ = stdcopy.StdCopy(stdoutW, stderrW, attach.Reader)
		stdoutW.Close()
		stderrW.Close()
	}()

	// stdout do tail
	go func() {
		sc := bufio.NewScanner(stdoutR)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line != "" {
				processor.ProcessLogs([]string{line})
				if debug {
					fmt.Printf(Blue+"[DEBUG][docker-tail] %s"+Reset+"\n", line)
				}
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Printf(Yellow+"[WARNING] docker-tail stdout scanner error: %v"+Reset+"\n", err)
		}
	}()

	// stderr do tail
	go func() {
		sc := bufio.NewScanner(stderrR)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r\n")
			if line != "" {
				processor.ProcessLogs([]string{line})
				if debug {
					fmt.Printf(Blue+"[DEBUG][docker-tail-err] %s"+Reset+"\n", line)
				}
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Printf(Yellow+"[WARNING] docker-tail stderr scanner error: %v"+Reset+"\n", err)
		}
	}()

	// inicia o exec
	if err := cli.ContainerExecStart(ctx, execIDResp.ID, types.ExecStartCheck{Tty: false}); err != nil {
		fmt.Printf(Yellow+"[WARNING] ContainerExecStart failed: %v"+Reset+"\n", err)
		return
	}
}

// --------- util ---------

func getZonesForProvider(cfg *config.Config, providerName string) []string {
	switch providerName {
	case "AWS Route53":
		return cfg.AWS.Route53Zones
	default:
		return []string{}
	}
}

func printBanner() {
	fmt.Println(Magenta + "========================================" + Reset)
	fmt.Println(Magenta + "     IDS/IPS Reverse Lookup Detector    " + Reset)
	fmt.Println(Magenta + "   -----------------------------------  " + Reset)
	fmt.Println(Magenta + "     Author : Gabriel Garcia            " + Reset)
	fmt.Printf(Magenta+"     Version: %s (Built: %s)         "+Reset+"\n", version, buildDate)
	fmt.Println(Magenta + "========================================" + Reset)
	fmt.Println()
}

func printVersion() {
	fmt.Printf("Reverse Lookup Detector v%s\n", version)
	fmt.Printf("Build date: %s\n", buildDate)
	fmt.Println("Author: Gabriel Garcia")
	fmt.Println("License: MIT")
	fmt.Println("Supported providers: AWS Route53 + BIND9 logs")
}

func setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		handleShutdown(sig)
	}()
}

func handleShutdown(sig os.Signal) {
	fmt.Printf(Yellow+"[INFO] Received signal %s. Terminating gracefully..."+Reset+"\n", sig)
	os.Exit(0)
}


