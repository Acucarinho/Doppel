package detector

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// DNSLogProcessor handles detection and analysis of DNS reverse lookups
type DNSLogProcessor struct {
	DetectionCount  int
	LastDetection   time.Time
	DebugMode       bool
	AlertThreshold  int
	detectedIPs     map[string]time.Time
	recentDetections []string
	patterns        []*regexp.Regexp
}

// NewDNSLogProcessor creates a new DNS log processor with optimized pattern matching
func NewDNSLogProcessor(debug bool, threshold int) *DNSLogProcessor {
	processor := &DNSLogProcessor{
		DebugMode:      debug,
		AlertThreshold: threshold,
		detectedIPs:    make(map[string]time.Time),
		recentDetections: make([]string, 0),
	}
	
	// Pre-compile regex patterns for better performance
	processor.patterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)PTR`),
		regexp.MustCompile(`(?i)in-addr\.arpa`),
		regexp.MustCompile(`(?i)reverse.*lookup`),
		regexp.MustCompile(`(?i)dns.*reverse`),
		regexp.MustCompile(`\d+\.\d+\.\d+\.\d+\.in-addr\.arpa`),
		regexp.MustCompile(`(?i)query.*type.*ptr`),
	}
	
	return processor
}

// ProcessLogs analyzes DNS log entries for reverse lookup patterns
func (p *DNSLogProcessor) ProcessLogs(logs []string) {
	currentDetections := 0
	
	for _, entry := range logs {
		if p.IsReverseLookup(entry) {
			currentDetections++
			ip := p.ExtractIPFromLog(entry)
			p.HandleDetection(entry, ip)
		} else if p.DebugMode {
			fmt.Println("[DEBUG] Normal log entry:", sanitizeEntry(entry))
		}
	}
	
	if currentDetections > 0 && p.DebugMode {
		fmt.Printf("[DEBUG] Processed %d logs, found %d reverse lookups\n", 
			len(logs), currentDetections)
	}
}

// IsReverseLookup checks if a log entry contains reverse DNS lookup patterns
func (p *DNSLogProcessor) IsReverseLookup(entry string) bool {
	normalized := strings.ToLower(strings.TrimSpace(entry))
	
	// Check against pre-compiled regex patterns
	for _, pattern := range p.patterns {
		if pattern.MatchString(normalized) {
			return true
		}
	}
	
	return false
}

// ExtractIPFromLog extracts IP addresses from log entries
func (p *DNSLogProcessor) ExtractIPFromLog(entry string) string {
	// Multiple IP extraction strategies
	ipPatterns := []*regexp.Regexp{
		regexp.MustCompile(`from\s+(\d+\.\d+\.\d+\.\d+)`),
		regexp.MustCompile(`client[_-]ip[=:]\s*(\d+\.\d+\.\d+\.\d+)`),
		regexp.MustCompile(`src[=:]\s*(\d+\.\d+\.\d+\.\d+)`),
		regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*in-addr\.arpa`),
	}
	
	for _, pattern := range ipPatterns {
		matches := pattern.FindStringSubmatch(entry)
		if len(matches) > 1 {
			ip := matches[1]
			if isValidIP(ip) {
				return ip
			}
		}
	}
	
	// Fallback: simple space-separated extraction
	parts := strings.Fields(entry)
	for _, part := range parts {
		if isValidIP(part) {
			return part
		}
	}
	
	return "unknown"
}

// HandleDetection processes a detected reverse lookup event
func (p *DNSLogProcessor) HandleDetection(entry string, ip string) {
	p.DetectionCount++
	p.LastDetection = time.Now()
	
	// Track detected IPs with timestamp
	if ip != "unknown" {
		p.detectedIPs[ip] = p.LastDetection
		p.recentDetections = append(p.recentDetections, ip)
		
		// Keep only recent detections (last 100)
		if len(p.recentDetections) > 100 {
			p.recentDetections = p.recentDetections[1:]
		}
	}
	
	p.RecordDetection(entry, ip)
	
	if p.DebugMode {
		p.PrintDiscreetAlert(entry, ip)
	}
	
	// Check if we need to escalate the alert
	if p.DetectionCount >= p.AlertThreshold {
		p.EscalateAlert(entry)
	}
}

// RecordDetection logs detection information
func (p *DNSLogProcessor) RecordDetection(entry string, ip string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	var ipInfo string
	if ip != "unknown" {
		ipInfo = fmt.Sprintf("from %s", ip)
	}
	
	logMsg := fmt.Sprintf("[MONITOR] %s - Reverse lookup detected %s (%d total)", 
		timestamp, ipInfo, p.DetectionCount)
	
	fmt.Println(logMsg)
	
	if p.DebugMode {
		fmt.Printf("[DETAIL] Entry: %s\n", sanitizeEntry(entry))
	}
}

// PrintDiscreetAlert shows a subtle alert for detected reverse lookups
func (p *DNSLogProcessor) PrintDiscreetAlert(entry string, ip string) {
	cyan := "\033[36m"
	reset := "\033[0m"
	
	var ipInfo string
	if ip != "unknown" {
		ipInfo = fmt.Sprintf(" (IP: %s)", ip)
	}
	
	fmt.Printf("%s[INFO] DNS monitoring activity detected%s: %s%s\n", 
		cyan, reset, sanitizeEntry(entry), ipInfo)
}

// EscalateAlert triggers a higher-level alert when threshold is reached
func (p *DNSLogProcessor) EscalateAlert(entry string) {
	yellow := "\033[33m"
	reset := "\033[0m"
	
	fmt.Printf("%s[ALERT] Multiple reverse lookups detected! (%d events)%s\n", 
		yellow, p.DetectionCount, reset)
	fmt.Printf("%s[ACTION] Consider changing infrastructure or investigating source%s\n", 
		yellow, reset)
	
	// Additional escalation actions could be added here:
	// - Send email alert
	// - Trigger webhook
	// - Log to external system
}

// GetStats returns current detection statistics
func (p *DNSLogProcessor) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_detections":  p.DetectionCount,
		"last_detection":    p.LastDetection,
		"alert_threshold":   p.AlertThreshold,
		"debug_mode":        p.DebugMode,
		"unique_ips":        len(p.detectedIPs),
		"recent_detections": len(p.recentDetections),
	}
}

// GetDetectedIPs returns all unique detected IP addresses
func (p *DNSLogProcessor) GetDetectedIPs() []string {
	ips := make([]string, 0, len(p.detectedIPs))
	for ip := range p.detectedIPs {
		ips = append(ips, ip)
	}
	return ips
}

// GetRecentDetectedIPs returns IPs from recent detections
func (p *DNSLogProcessor) GetRecentDetectedIPs() []string {
	// Return copy to prevent external modification
	recent := make([]string, len(p.recentDetections))
	copy(recent, p.recentDetections)
	return recent
}

// GetIPDetectionTime returns when a specific IP was first detected
func (p *DNSLogProcessor) GetIPDetectionTime(ip string) (time.Time, bool) {
	detectionTime, exists := p.detectedIPs[ip]
	return detectionTime, exists
}

// ResetStats clears all detection statistics
func (p *DNSLogProcessor) ResetStats() {
	p.DetectionCount = 0
	p.LastDetection = time.Time{}
	p.detectedIPs = make(map[string]time.Time)
	p.recentDetections = make([]string, 0)
	
	fmt.Println("[INFO] Detection statistics reset")
}

// GetDetectionSummary returns a formatted summary of detections
func (p *DNSLogProcessor) GetDetectionSummary() string {
	if p.DetectionCount == 0 {
		return "No reverse lookups detected"
	}
	
	return fmt.Sprintf("Detected %d reverse lookups from %d unique IPs. Last detection: %v",
		p.DetectionCount, len(p.detectedIPs), p.LastDetection.Format(time.RFC1123))
}

// sanitizeEntry removes sensitive information from log entries
func sanitizeEntry(entry string) string {
	// Remove potential sensitive data
	entry = regexp.MustCompile(`(?i)api[_-]?key[=:][^ ]+`).ReplaceAllString(entry, "api_key=***")
	entry = regexp.MustCompile(`(?i)auth[=:][^ ]+`).ReplaceAllString(entry, "auth=***")
	entry = regexp.MustCompile(`(?i)token[=:][^ ]+`).ReplaceAllString(entry, "token=***")
	
	// Partial IP obfuscation
	parts := strings.Fields(entry)
	for i, part := range parts {
		if isValidIP(part) {
			// Obfuscate first two octets
			octets := strings.Split(part, ".")
			if len(octets) == 4 {
				parts[i] = fmt.Sprintf("xxx.xxx.%s.%s", octets[2], octets[3])
			}
		}
	}
	return strings.Join(parts, " ")
}

// isValidIP checks if a string is a valid IPv4 address
func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// IsHighFrequencyDetection checks if detections are happening rapidly
func (p *DNSLogProcessor) IsHighFrequencyDetection(timeWindow time.Duration, threshold int) bool {
	if p.DetectionCount < threshold {
		return false
	}
	
	// Check if we've had more than 'threshold' detections in the time window
	cutoff := time.Now().Add(-timeWindow)
	count := 0
	
	for _, detectionTime := range p.detectedIPs {
		if detectionTime.After(cutoff) {
			count++
		}
	}
	
	return count >= threshold
}
