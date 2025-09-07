package dohserver

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"doppel/internal/detector"
	"doppel/internal/rotator"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
)

// DoHServer implementa um servidor DNS over HTTPS fake
type DoHServer struct {
	processor       *detector.DNSLogProcessor
	port            int
	certFile        string
	keyFile         string
	domain          string
	debug           bool
	useLetsEncrypt  bool
	realisticDelay  bool
	innocentDomains map[string]bool
	certRotator     *rotator.CertificateManager // Novo: rotator de certificados
}

// DoHRequest representa uma requisição DoH
type DoHRequest struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	QueryID int    `json:"query_id,omitempty"`
}

// DoHResponse representa uma resposta DoH
type DoHResponse struct {
	Status    int                      `json:"Status"`
	TC        bool                     `json:"TC"`
	RD        bool                     `json:"RD"`
	RA        bool                     `json:"RA"`
	AD        bool                     `json:"AD"`
	CD        bool                     `json:"CD"`
	Question  []map[string]interface{} `json:"Question"`
	Answer    []map[string]interface{} `json:"Answer"`
	Authority []map[string]interface{} `json:"Authority,omitempty"`
}

// NewDoHServer cria uma nova instância do servidor DoH fake
func NewDoHServer(processor *detector.DNSLogProcessor, port int, certFile, keyFile, domain string, debug, useLetsEncrypt, realisticDelay bool) *DoHServer {
	server := &DoHServer{
		processor:      processor,
		port:           port,
		certFile:       certFile,
		keyFile:        keyFile,
		domain:         domain,
		debug:          debug,
		useLetsEncrypt: false, // Desabilitar Let's Encrypt
		realisticDelay: realisticDelay,
		innocentDomains: map[string]bool{
			"tatic.isp.com":                 true,
			"metrics.icloud.com":            true,
			"time.apple.com":                true,
			"captive.apple.com":             true,
			"www.google.com":                true,
			"connectivitycheck.gstatic.com": true,
		},
	}

	// Inicializar o rotator de certificados
	certDir := "/tmp/certs"
	server.certRotator = rotator.NewCertificateManager(certDir, true, false, false, 24*time.Hour)
	
	// Clonar certificados de sites populares automaticamente
	go server.clonePopularCertificates()

	return server
}

// clonePopularCertificates clona certificados de sites populares em background
func (s *DoHServer) clonePopularCertificates() {
	time.Sleep(2 * time.Second) // Esperar inicialização
	
	popularSites := []string{
		"cloudflare.com",
		"google.com", 
		"facebook.com",
		"amazon.com",
		"microsoft.com",
	}

	for _, site := range popularSites {
		if _, err := s.certRotator.CloneCertificate(site, 443, site); err != nil {
			if s.debug {
				log.Printf("Failed to clone certificate from %s: %v", site, err)
			}
		} else if s.debug {
			log.Printf("Successfully cloned certificate from %s", site)
		}
	}
}

// checkCertificates verifica se os certificados estão disponíveis
func (s *DoHServer) checkCertificates() error {
	// Verificar se temos certificados no rotator
	if s.certRotator == nil {
		return fmt.Errorf("certificate rotator not initialized")
	}

	// Para certificados personalizados, verificar se os arquivos existem
	if s.certFile != "" && s.keyFile != "" {
		if _, err := os.Stat(s.certFile); os.IsNotExist(err) {
			return fmt.Errorf("certificate file does not exist: %s", s.certFile)
		}
		if _, err := os.Stat(s.keyFile); os.IsNotExist(err) {
			return fmt.Errorf("private key file does not exist: %s", s.keyFile)
		}
	}

	return nil
}

// Start inicia o servidor DoH
func (s *DoHServer) Start() error {
	// Verificar certificados antes de iniciar
	if err := s.checkCertificates(); err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	router := mux.NewRouter()

	// Endpoints principais DoH
	router.HandleFunc("/dns-query", s.handleDoHQuery).Methods("GET", "POST")
	router.HandleFunc("/resolve", s.handleDoHQuery).Methods("GET", "POST")
	router.HandleFunc("/query", s.handleDoHQuery).Methods("GET", "POST")
	router.HandleFunc("/.well-known/dns-query", s.handleDoHQuery).Methods("GET", "POST")
	router.HandleFunc("/health", s.handleHealthCheck).Methods("GET")

	// Configurar servidor HTTP/2
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Configuração TLS - Prioridade: Certificados personalizados > Rotator
	if s.certFile != "" && s.keyFile != "" {
		// Usar certificados existentes
		server.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		}

		log.Printf("Starting DoH server with custom TLS on port %d", s.port)
		return server.ListenAndServeTLS(s.certFile, s.keyFile)
	} else {
		// Usar rotator de certificados
		server.TLSConfig = &tls.Config{
			GetCertificate: s.certRotator.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
			MinVersion:     tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}

		// Iniciar rotação automática de certificados
		s.certRotator.StartCertificateRotation()

		log.Printf("Starting DoH server with certificate rotation on port %d", s.port)
		return server.ListenAndServeTLS("", "")
	}
}

// handleDoHQuery processa consultas DoH (mantido igual)
func (s *DoHServer) handleDoHQuery(w http.ResponseWriter, r *http.Request) {
	// Simular tempo de resposta realista
	if s.realisticDelay {
		delay := time.Duration(rand.Intn(100)+50) * time.Millisecond
		time.Sleep(delay)
	}

	// Definir cabeçalhos idênticos aos servidores reais
	w.Header().Set("Content-Type", "application/dns-json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("CF-RAY", generateCloudflareRayID())

	// Handle CORS preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var dohRequest DoHRequest
	var clientIP string
	var domainName string
	var queryType string

	// Obter IP do cliente
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	} else {
		clientIP = r.RemoteAddr
	}

	// Registrar a requisição
	if s.debug {
		log.Printf("DoH request from %s: %s %s", clientIP, r.Method, r.URL.String())
	}

	// Processar diferentes métodos de requisição
	switch r.Method {
	case "GET":
		dnsParam := r.URL.Query().Get("dns")
		nameParam := r.URL.Query().Get("name")
		typeParam := r.URL.Query().Get("type")

		if dnsParam != "" {
			if decoded, err := base64.RawURLEncoding.DecodeString(dnsParam); err == nil {
				domainName, queryType = s.extractDomainFromDNSMessage(decoded)
			}
		} else if nameParam != "" {
			domainName = nameParam
			queryType = typeParam
			if queryType == "" {
				queryType = "A"
			}
		} else {
			http.Error(w, "Missing parameters", http.StatusBadRequest)
			return
		}

	case "POST":
		if r.Header.Get("Content-Type") == "application/dns-json" {
			if err := json.NewDecoder(r.Body).Decode(&dohRequest); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
			domainName = dohRequest.Name
			queryType = dohRequest.Type
		} else if r.Header.Get("Content-Type") == "application/dns-message" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Error reading body", http.StatusBadRequest)
				return
			}
			domainName, queryType = s.extractDomainFromDNSMessage(body)
		} else {
			http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if domainName == "" {
		http.Error(w, "Invalid DNS query", http.StatusBadRequest)
		return
	}

	// Registrar a consulta no detector
	logEntry := fmt.Sprintf("%s DoH_Query %s %s %s NOERROR", 
		time.Now().Format(time.RFC3339), clientIP, domainName, queryType)

	s.processor.ProcessLogs([]string{logEntry})

	if s.debug {
		log.Printf("Processed DoH query: %s %s from %s", domainName, queryType, clientIP)
	}

	// Gerar resposta
	response := s.generateResponse(domainName, queryType, clientIP)

	// Enviar resposta
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// extractDomainFromDNSMessage extrai domínio e tipo usando biblioteca DNS adequada
func (s *DoHServer) extractDomainFromDNSMessage(data []byte) (string, string) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	if err != nil {
		if s.debug {
			log.Printf("Failed to parse DNS message: %v", err)
		}
		return "unknown.domain", "A"
	}

	if len(msg.Question) == 0 {
		return "unknown.domain", "A"
	}

	question := msg.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	qtype := dns.TypeToString[question.Qtype]

	if qtype == "" {
		qtype = "A"
	}

	return domain, qtype
}

// generateResponse cria uma resposta DNS realista
func (s *DoHServer) generateResponse(domain, queryType, clientIP string) DoHResponse {
	// Verificar se é um domínio suspeito que precisa de redirecionamento
	redirectDomain := s.checkForRedirect(domain, queryType)

	// Resposta base
	response := DoHResponse{
		Status: 0, // NOERROR
		TC:     false,
		RD:     true,
		RA:     true,
		AD:     false, // Desabilitar DNSSEC para parecer mais comum
		CD:     false,
		Question: []map[string]interface{}{
			{
				"name": domain,
				"type": typeToCode(queryType),
			},
		},
	}

	// Adicionar respostas baseadas no tipo de consulta
	switch queryType {
	case "A":
		response.Answer = []map[string]interface{}{
			{
				"name": redirectDomain,
				"type": 1, // A
				"TTL":  300,
				"data": s.generateARecord(redirectDomain),
			},
		}
	case "AAAA":
		response.Answer = []map[string]interface{}{
			{
				"name": redirectDomain,
				"type": 28, // AAAA
				"TTL":  300,
				"data": s.generateAAAARecord(redirectDomain),
			},
		}
	case "PTR":
		// Para consultas PTR, redirecionar para domínio inocente
		response.Answer = []map[string]interface{}{
			{
				"name": domain,
				"type": 12, // PTR
				"TTL":  300,
				"data": "tatic.isp.com.", // Domínio inocente
			},
		}
	case "MX":
		response.Answer = []map[string]interface{}{
			{
				"name": redirectDomain,
				"type": 15, // MX
				"TTL":  300,
				"data": fmt.Sprintf("10 mail.%s.", redirectDomain),
			},
		}
	case "TXT":
		response.Answer = []map[string]interface{}{
			{
				"name": redirectDomain,
				"type": 16, // TXT
				"TTL":  300,
				"data": "\"v=spf1 include:spf.protection.outlook.com -all\"",
			},
		}
	default:
		// Para tipos desconhecidos, retornar resposta vazia
		response.Answer = []map[string]interface{}{}
	}

	return response
}

// checkForRedirect verifica se o domínio precisa ser redirecionado
func (s *DoHServer) checkForRedirect(domain, queryType string) string {
	// Lista de domínios suspeitos que devem be redirecionados
	suspiciousDomains := map[string]bool{
		"malicious.com": true,
		"evil.org":      true,
		"phishing.net":  true,
		"c2-server.com": true,
	}

	// Para consultas PTR (reverse DNS), sempre redirecionar
	if queryType == "PTR" {
		return "tatic.isp.com"
	}

	// Verificar se o domínio está na lista de suspeitos
	if suspiciousDomains[domain] {
		return "tatic.isp.com"
	}

	// Para outros domínios, retornar o domínio original
	return domain
}

// generateARecord gera um registro A realista
func (s *DoHServer) generateARecord(domain string) string {
	// Mapeamento de domínios para IPs realistas
	domainIPs := map[string]string{
		"tatic.isp.com":                 "93.184.216.34",   // example.com
		"google.com":                    "142.251.132.206", // google.com
		"facebook.com":                  "157.240.241.35",  // facebook.com
		"cloudflare.com":                "104.16.132.229",  // cloudflare.com
		"metrics.icloud.com":            "17.57.144.84",    // apple
		"time.apple.com":                "17.253.83.205",   // apple
		"captive.apple.com":             "17.253.22.204",   // apple
		"www.google.com":                "142.251.132.196", // google
		"connectivitycheck.gstatic.com": "142.251.32.238",  // google
	}

	if ip, exists := domainIPs[domain]; exists {
		return ip
	}

	// Gerar IP aleatório para domínios não mapeados
	return fmt.Sprintf("%d.%d.%d.%d", 
		rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

// generateAAAARecord gera um registro AAAA realista
func (s *DoHServer) generateAAAARecord(domain string) string {
	// Mapeamento de domínios para IPv6 realistas
	domainIPv6s := map[string]string{
		"tatic.isp.com": "2606:2800:220:1:248:1893:25c8:1946", // example.com
		"google.com":    "2a00:1450:4001:80e::200e",           // google.com
		"facebook.com":  "2a03:2880:f10e:83:face:b00c:0:25de", // facebook.com
	}

	if ipv6, exists := domainIPv6s[domain]; exists {
		return ipv6
	}

	// Gerar IPv6 aleatório para domínios não mapeados
	return fmt.Sprintf("2001:%x:%x:%x:%x:%x:%x:%x",
		rand.Intn(65535), rand.Intn(65535), rand.Intn(65535),
		rand.Intn(65535), rand.Intn(65535), rand.Intn(65535),
		rand.Intn(65535))
}

// handleHealthCheck endpoint para verificação de saúde
func (s *DoHServer) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// handleMetrics endpoint para métricas
func (s *DoHServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Server", "cloudflare")
	fmt.Fprintf(w, "# HELP doh_requests_total Total number of DoH requests\n")
	fmt.Fprintf(w, "# TYPE doh_requests_total counter\n")
	fmt.Fprintf(w, "doh_requests_total{protocol=\"https\"} %d\n", rand.Intn(1000)+500)
}

// generateCloudflareRayID gera um ID de ray do Cloudflare fake
func generateCloudflareRayID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return fmt.Sprintf("%s-%04x", string(b), rand.Intn(65535))
}

// typeToCode converte tipo DNS string para código numérico
func typeToCode(queryType string) int {
	typeMap := map[string]int{
		"A":      1,
		"NS":     2,
		"CNAME":  5,
		"SOA":    6,
		"MX":     15,
		"TXT":    16,
		"AAAA":   28,
		"PTR":    12,
	}

	if code, exists := typeMap[queryType]; exists {
		return code
	}
	return 1 // Padrão para tipo A
}