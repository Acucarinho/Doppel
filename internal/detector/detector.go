package detector

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DNSLogProcessor struct {
	// Estatísticas
	DetectionCount   int
	LastDetection    time.Time
	DebugMode        bool
	AlertThreshold   int

	// Estado
	detectedIPs      map[string]time.Time
	recentDetections []string

	// Contador por ciclo (para alertar no próximo ciclo)
	cycleDetections int

	// Regex pré-compilados
	// Exemplos de linhas do BIND:
	//   "... query: darkinfrac2.local IN A +E(0)K (172.18.0.2)"
	//   "... query: darkinfrac2.local A +E(0)K (172.18.0.2)"
	anyQueryWithIN *regexp.Regexp
	anyQueryNoIN   *regexp.Regexp
	clientIPRE     *regexp.Regexp

	// Mutex para proteger tudo que é mutável e acessado por goroutines
	mu sync.Mutex
}

// Para compatibilidade com quem quiser enviar uma única linha como “consulta”
type DNSQuery struct {
	Timestamp time.Time `json:"timestamp"`
	ClientIP  string    `json:"client_ip"`
	QueryType string    `json:"query_type"`
	Domain    string    `json:"domain"`
	RawLog    string    `json:"raw_log"`
}

func (p *DNSLogProcessor) ProcessQuery(q DNSQuery) { p.ProcessLogs([]string{q.RawLog}) }

func NewDNSLogProcessor(debug bool, threshold int) *DNSLogProcessor {
	return &DNSLogProcessor{
		DebugMode:        debug,
		AlertThreshold:   threshold,
		detectedIPs:      make(map[string]time.Time),
		recentDetections: make([]string, 0, 128),
		anyQueryWithIN:   regexp.MustCompile(`(?i)\bquery:\s+([^\s]+)\s+IN\s+(A|AAAA|PTR)\b`),
		anyQueryNoIN:     regexp.MustCompile(`(?i)\bquery:\s+([^\s]+)\s+(A|AAAA|PTR)\b`),
		clientIPRE:       regexp.MustCompile(`(?i)\bclient\b(?:\s+@[^\s]+)?\s+(\d+\.\d+\.\d+\.\d+)#\d+`),
	}
}

// Processa um lote de linhas de log (chamado pelas goroutines do Docker)
func (p *DNSLogProcessor) ProcessLogs(logs []string) {
	found := 0
	for _, entry := range logs {
		qname, qtype, clientIP := p.parse(entry)
		if qtype == "" {
			if p.DebugMode {
				fmt.Println("[DEBUG] Normal log entry:", sanitizeEntry(entry))
			}
			continue
		}
		if clientIP == "" {
			clientIP = p.extractIPFromLog(entry)
		}
		if clientIP == "" {
			clientIP = "unknown"
		}

		found++
		p.handleDetection(entry, clientIP, qtype, qname)
	}

	if found > 0 && p.DebugMode {
		fmt.Printf("[DEBUG] Processed %d logs, detected %d DNS queries (A/AAAA/PTR)\n", len(logs), found)
	}
}

// Extrai qname, qtype e client IP tolerando variações
func (p *DNSLogProcessor) parse(s string) (qname, qtype, clientIP string) {
	line := strings.TrimSpace(s)

	if m := p.anyQueryWithIN.FindStringSubmatch(line); len(m) == 3 {
		qname, qtype = m[1], strings.ToUpper(m[2])
	} else if m := p.anyQueryNoIN.FindStringSubmatch(line); len(m) == 3 {
		qname, qtype = m[1], strings.ToUpper(m[2])
	}

	if m := p.clientIPRE.FindStringSubmatch(line); len(m) == 2 {
		clientIP = m[1]
	}
	return
}

func (p *DNSLogProcessor) extractIPFromLog(entry string) string {
	ipPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\bfrom\s+(\d+\.\d+\.\d+\.\d+)\b`),
		regexp.MustCompile(`\bclient[_-]?ip[=:]\s*(\d+\.\d+\.\d+\.\d+)\b`),
		regexp.MustCompile(`\bsrc[=:]\s*(\d+\.\d+\.\d+\.\d+)\b`),
		regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*in-addr\.arpa`),
	}
	for _, r := range ipPatterns {
		if m := r.FindStringSubmatch(entry); len(m) > 1 && isValidIP(m[1]) {
			return m[1]
		}
	}
	for _, part := range strings.Fields(entry) {
		if isValidIP(part) {
			return part
		}
	}
	return ""
}

// Único caminho de detecção: atualiza estado sob mutex e imprime
func (p *DNSLogProcessor) handleDetection(entry, clientIP, qtype, qname string) {
	p.mu.Lock()
	p.DetectionCount++
	p.cycleDetections++
	p.LastDetection = time.Now()

	if clientIP != "" && clientIP != "unknown" {
		p.detectedIPs[clientIP] = p.LastDetection
		p.recentDetections = append(p.recentDetections, clientIP)
		if len(p.recentDetections) > 200 {
			p.recentDetections = p.recentDetections[1:]
		}
	}
	p.mu.Unlock()

	p.recordDetection(entry, clientIP, qtype, qname)

	if p.DebugMode {
		p.printDiscreetAlert(entry, clientIP, qtype, qname)
	}

	// Alerta imediato (limiar global)
	p.mu.Lock()
	needEscalate := p.DetectionCount >= p.AlertThreshold
	p.mu.Unlock()
	if needEscalate {
		p.escalateAlert()
	}
}

func (p *DNSLogProcessor) recordDetection(entry, clientIP, qtype, qname string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	ipInfo := ""
	if clientIP != "" && clientIP != "unknown" {
		ipInfo = " from " + clientIP
	}
	fmt.Printf("[MONITOR] %s - DNS query detected: %s %s%s\n", ts, qtype, qname, ipInfo)

	if p.DebugMode {
		fmt.Printf("[DETAIL] Entry: %s\n", sanitizeEntry(entry))
	}
}

func (p *DNSLogProcessor) printDiscreetAlert(entry, clientIP, qtype, qname string) {
	cyan, reset := "\033[36m", "\033[0m"
	ipInfo := ""
	if clientIP != "" && clientIP != "unknown" {
		ipInfo = " (IP: " + clientIP + ")"
	}
	fmt.Printf("%s[INFO] DNS activity%s: %s %s%s%s\n", cyan, reset, qtype, qname, ipInfo, reset)
}

// Alerta quando o limiar global é atingido
func (p *DNSLogProcessor) escalateAlert() {
	yellow, reset := "\033[33m", "\033[0m"
	fmt.Printf("%s[ALERT] Multiple DNS queries detected! (%d events)%s\n", yellow, p.DetectionCount, reset)
	fmt.Printf("%s[ACTION] Investigate potential reconnaissance or misconfiguration%s\n", yellow, reset)
}

// ——— APIs consultadas pelo main ———

func (p *DNSLogProcessor) GetStats() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]interface{}{
		"total_detections":  p.DetectionCount,
		"last_detection":    p.LastDetection,
		"alert_threshold":   p.AlertThreshold,
		"debug_mode":        p.DebugMode,
		"unique_ips":        len(p.detectedIPs),
		"recent_detections": len(p.recentDetections),
	}
}

func (p *DNSLogProcessor) GetDetectedIPs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	ips := make([]string, 0, len(p.detectedIPs))
	for ip := range p.detectedIPs {
		ips = append(ips, ip)
	}
	return ips
}

func (p *DNSLogProcessor) GetRecentDetectedIPs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.recentDetections))
	copy(out, p.recentDetections)
	return out
}

func (p *DNSLogProcessor) GetIPDetectionTime(ip string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.detectedIPs[ip]
	return t, ok
}

func (p *DNSLogProcessor) ResetStats() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.DetectionCount = 0
	p.LastDetection = time.Time{}
	p.detectedIPs = make(map[string]time.Time)
	p.recentDetections = make([]string, 0, 128)
	p.cycleDetections = 0
	fmt.Println("[INFO] Detection statistics reset")
}

// Chamado pelo main no FIM de cada ciclo para saber se deve imprimir
// o CRITICAL no próximo ciclo.
func (p *DNSLogProcessor) GetAndResetCycleDetections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.cycleDetections
	p.cycleDetections = 0
	return c
}

// ——— util ———

func sanitizeEntry(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	entry = regexp.MustCompile(`(?i)api[_-]?key[=:][^ ]+`).ReplaceAllString(entry, "api_key=***")
	entry = regexp.MustCompile(`(?i)auth[=:][^ ]+`).ReplaceAllString(entry, "auth=***")
	entry = regexp.MustCompile(`(?i)token[=:][^ ]+`).ReplaceAllString(entry, "token=***")
	return entry
}

func isValidIP(ip string) bool {
	ipn := net.ParseIP(ip)
	return ipn != nil && ipn.To4() != nil
}

// Alta frequência (heurstica simples por janela)
func (p *DNSLogProcessor) IsHighFrequencyDetection(win time.Duration, threshold int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.DetectionCount < threshold {
		return false
	}
	cutoff := time.Now().Add(-win)
	cnt := 0
	for _, t := range p.detectedIPs {
		if t.After(cutoff) {
			cnt++
		}
	}
	return cnt >= threshold
}

