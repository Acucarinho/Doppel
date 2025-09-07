package rotator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http" 
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// CertificateManager gerencia a clonagem e rotação de certificados
type CertificateManager struct {
	certCache    map[string]*tls.Certificate
	certDir      string
	reuseKeys    bool
	keepIssuer   bool
	keepSerial   bool
	rotationTime time.Duration
}

// NewCertificateManager cria um novo gerenciador de certificados
func NewCertificateManager(certDir string, reuseKeys, keepIssuer, keepSerial bool, rotationTime time.Duration) *CertificateManager {
	os.MkdirAll(certDir, 0755)
	return &CertificateManager{
		certCache:    make(map[string]*tls.Certificate),
		certDir:      certDir,
		reuseKeys:    reuseKeys,
		keepIssuer:   keepIssuer,
		keepSerial:   keepSerial,
		rotationTime: rotationTime,
	}
}

// CloneCertificate clona um certificado de um host remoto
func (cm *CertificateManager) CloneCertificate(host string, port int, sni string) (*tls.Certificate, error) {
	// Conectar ao host e obter o certificado
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Obter o certificado do servidor
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates received")
	}

	serverCert := state.PeerCertificates[0]
	return cm.CloneX509Certificate(serverCert)
}

// CloneX509Certificate clona um certificado x509 existente
func (cm *CertificateManager) CloneX509Certificate(originalCert *x509.Certificate) (*tls.Certificate, error) {
	cacheKey := originalCert.Subject.CommonName + originalCert.SerialNumber.String()
	if cert, exists := cm.certCache[cacheKey]; exists && cm.reuseKeys {
		return cert, nil
	}

	// Gerar nova chave privada
	var privKey *rsa.PrivateKey
	var err error

	if cm.reuseKeys {
		privKey, err = cm.loadOrGenerateRSAKey(originalCert)
	} else {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, err
	}

	// Criar certificado clonado
	clonedCert := &x509.Certificate{
		SerialNumber: originalCert.SerialNumber,
		Subject:      originalCert.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     originalCert.KeyUsage,
		ExtKeyUsage:  originalCert.ExtKeyUsage,
		DNSNames:     originalCert.DNSNames,
		IPAddresses:  originalCert.IPAddresses,
	}

	// Modificar issuer se necessário
	if !cm.keepIssuer && originalCert.Issuer.CommonName != originalCert.Subject.CommonName {
		clonedCert.Issuer = cm.modifyIssuer(originalCert.Issuer)
	} else {
		clonedCert.Issuer = originalCert.Issuer
	}

	// Modificar serial se necessário
	if !cm.keepSerial && originalCert.Issuer.CommonName != originalCert.Subject.CommonName {
		clonedCert.SerialNumber = cm.generateSerialNumber()
	}

	// Assinar o certificado
	certDER, err := x509.CreateCertificate(rand.Reader, clonedCert, clonedCert, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Converter para TLS Certificate
	tlsCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	tlsCertificate := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
		Leaf:        tlsCert,
	}

	// Armazenar em cache
	cm.certCache[cacheKey] = tlsCertificate

	// Salvar em arquivo
	err = cm.saveCertificateToFile(tlsCertificate, originalCert.Subject.CommonName)
	if err != nil {
		log.Printf("Warning: failed to save certificate: %v", err)
	}

	return tlsCertificate, nil
}

func (cm *CertificateManager) loadOrGenerateRSAKey(originalCert *x509.Certificate) (*rsa.PrivateKey, error) {
	keyFile := filepath.Join(cm.certDir, "rsa_2048.key")
	
	if cm.reuseKeys {
		if data, err := ioutil.ReadFile(keyFile); err == nil {
			block, _ := pem.Decode(data)
			if block != nil {
				return x509.ParsePKCS1PrivateKey(block.Bytes)
			}
		}
	}

	// Gerar nova chave
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Salvar chave
	keyData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	if err := ioutil.WriteFile(keyFile, keyData, 0600); err != nil {
		log.Printf("Warning: failed to save key: %v", err)
	}

	return privKey, nil
}

func (cm *CertificateManager) modifyIssuer(original pkix.Name) pkix.Name {
	modified := original
	if modified.CommonName != "" {
		// Modificar ligeiramente o nome do issuer
		modified.CommonName = strings.Map(func(r rune) rune {
			switch r {
			case 'I':
				return 'l'
			case 'l':
				return 'I'
			case 'O':
				return '0'
			case '0':
				return 'O'
			default:
				return r
			}
		}, modified.CommonName)
	}
	return modified
}

func (cm *CertificateManager) generateSerialNumber() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

func (cm *CertificateManager) saveCertificateToFile(cert *tls.Certificate, baseName string) error {
	// Salvar certificado
	certFile := filepath.Join(cm.certDir, baseName+".crt")
	certData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})
	if err := ioutil.WriteFile(certFile, certData, 0644); err != nil {
		return err
	}

	// Salvar chave privada
	keyFile := filepath.Join(cm.certDir, baseName+".key")
	keyData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey)),
	})
	return ioutil.WriteFile(keyFile, keyData, 0600)
}

// StartCertificateRotation inicia a rotação automática de certificados
func (cm *CertificateManager) StartCertificateRotation() {
	ticker := time.NewTicker(cm.rotationTime)
	go func() {
		for range ticker.C {
			cm.rotateCertificates()
		}
	}()
}

func (cm *CertificateManager) rotateCertificates() {
	log.Println("Rotating certificates...")
	
	// Limpar cache e gerar novos certificados
	newCache := make(map[string]*tls.Certificate)
	
	for key, cert := range cm.certCache {
		// Clonar novamente cada certificado
		if clonedCert, err := cm.CloneX509Certificate(cert.Leaf); err == nil {
			newCache[key] = clonedCert
		} else {
			log.Printf("Failed to rotate certificate %s: %v", key, err)
			// Manter o antigo em caso de erro
			newCache[key] = cert
		}
	}
	
	cm.certCache = newCache
	log.Println("Certificate rotation completed")
}

// GetCertificate implementa a interface tls.Config.GetCertificate
func (cm *CertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := hello.ServerName
	if serverName == "" {
		serverName = "localhost"
	}

	// Verificar se já temos um certificado para este SNI
	for _, cert := range cm.certCache {
		if cert.Leaf != nil && (cert.Leaf.Subject.CommonName == serverName || 
			contains(cert.Leaf.DNSNames, serverName)) {
			return cert, nil
		}
	}

	// Se não encontrou, clonar do host original
	log.Printf("Cloning certificate for: %s", serverName)
	return cm.CloneCertificate(serverName, 443, serverName)
}

// CloneFromPopularSites clona certificados de sites populares
func (cm *CertificateManager) CloneFromPopularSites() error {
	popularSites := []string{
		"cloudflare.com",
		"google.com",
		"facebook.com",
		"amazon.com",
		"microsoft.com",
	}

	for _, site := range popularSites {
		if _, err := cm.CloneCertificate(site, 443, site); err != nil {
			log.Printf("Failed to clone certificate from %s: %v", site, err)
		} else {
			log.Printf("Successfully cloned certificate from %s", site)
		}
	}

	return nil
}

// ExportPFX exporta certificado e chave para formato PFX/P12
func (cm *CertificateManager) ExportPFX(cert *tls.Certificate, filename, password string) error {
	pfxData, err := pkcs12.Encode(rand.Reader, cert.PrivateKey, cert.Leaf, nil, password)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, pfxData, 0600)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	// Exemplo de uso
	certManager := NewCertificateManager("/tmp/certs", true, false, false, 24*time.Hour)
	
	// Clonar certificados de sites populares
	if err := certManager.CloneFromPopularSites(); err != nil {
		log.Fatalf("Failed to clone certificates: %v", err)
	}

	// Iniciar rotação automática
	certManager.StartCertificateRotation()

	// Configurar servidor HTTPS com certificados clonados
	server := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	log.Println("Starting HTTPS server with cloned certificates...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}