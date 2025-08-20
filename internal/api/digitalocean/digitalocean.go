package digitalocean

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"doppel/internal/config"
)

// DigitalOceanClient implements DNSProvider for DigitalOcean with change detection
type DigitalOceanClient struct {
	cfg         *config.Config
	HTTPClient  *http.Client
	lastFetch   time.Time
	recordCache map[string]map[string]DNSRecord // domain -> recordHash -> record
	lastHashes  map[string]string               // domain -> hash of all records
}

// DNSRecord represents a DigitalOcean DNS record with change detection
type DNSRecord struct {
	ID       int    `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	Priority int    `json:"priority"`
	Port     int    `json:"port"`
	TTL      int    `json:"ttl"`
	Weight   int    `json:"weight"`
	Flags    int    `json:"flags"`
	Tag      string `json:"tag"`
	Created  string `json:"created_at"`
	Updated  string `json:"updated_at"`
	Hash     string `json:"-"`
}

// ChangeType represents the type of DNS change detected
type ChangeType int

const (
	ChangeNone ChangeType = iota
	ChangeNewRecord
	ChangeModifiedRecord
	ChangeRemovedRecord
	ChangeIPAddress
	ChangeTXTRecord
	ChangeCNAMERecord
)

// ChangeResult represents a detected DNS change
type ChangeResult struct {
	Type        ChangeType
	Domain      string
	Record      DNSRecord
	OldRecord   *DNSRecord
	Description string
	Timestamp   time.Time
}

// NewDigitalOceanClient creates a new DigitalOcean API client with change detection
func NewDigitalOceanClient(cfg *config.Config) *DigitalOceanClient {
	return &DigitalOceanClient{
		cfg:         cfg,
		HTTPClient:  &http.Client{Timeout: time.Duration(cfg.Monitoring.TimeoutSeconds) * time.Second},
		recordCache: make(map[string]map[string]DNSRecord),
		lastHashes:  make(map[string]string),
		lastFetch:   time.Now().Add(-1 * time.Hour), // Force initial fetch
	}
}

// ProviderName returns the name of the provider
func (d *DigitalOceanClient) ProviderName() string {
	return "DigitalOcean"
}

// GetDNSLogs fetches current DNS records and detects changes
func (d *DigitalOceanClient) GetDNSLogs(domain string) ([]string, error) {
	if d.cfg.APIKeys.DigitalOcean == "" {
		return nil, fmt.Errorf("DigitalOcean API key not configured")
	}

	// Fetch current records
	currentRecords, err := d.getCurrentDNSRecords(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS records for %s: %v", domain, err)
	}

	// Detect changes
	changes, err := d.detectChanges(domain, currentRecords)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for %s: %v", domain, err)
	}

	// Generate logs from changes and current state
	logs := d.generateLogs(domain, currentRecords, changes)

	if len(logs) == 0 {
		return []string{fmt.Sprintf("%s [INFO] No changes detected for %s, %d records stable",
			time.Now().Format("2006-01-02 15:04:05"), domain, len(currentRecords))}, nil
	}

	return logs, nil
}

// detectChanges compares current records with cached records to find changes
func (d *DigitalOceanClient) detectChanges(domain string, currentRecords []DNSRecord) ([]ChangeResult, error) {
	var changes []ChangeResult
	now := time.Now()

	// Get previous records from cache
	previousRecords := d.recordCache[domain]
	if previousRecords == nil {
		// First run, initialize cache but don't report changes
		d.recordCache[domain] = make(map[string]DNSRecord)
		for _, record := range currentRecords {
			d.recordCache[domain][record.Hash] = record
		}
		d.lastHashes[domain] = d.calculateDomainHash(currentRecords)
		return nil, nil
	}

	// Calculate current domain hash for quick comparison
	currentHash := d.calculateDomainHash(currentRecords)
	previousHash := d.lastHashes[domain]

	// Quick check: if domain hash hasn't changed, no changes
	if currentHash == previousHash {
		return nil, nil
	}

	// Detailed comparison
	currentMap := make(map[string]DNSRecord)
	for _, record := range currentRecords {
		currentMap[record.Hash] = record
	}

	// Check for removed records
	for hash, oldRecord := range previousRecords {
		if _, exists := currentMap[hash]; !exists {
			changes = append(changes, ChangeResult{
				Type:        ChangeRemovedRecord,
				Domain:      domain,
				Record:      oldRecord,
				Description: fmt.Sprintf("Record removed: %s %s -> %s", oldRecord.Type, oldRecord.Name, oldRecord.Data),
				Timestamp:   now,
			})
		}
	}

	// Check for new or modified records
	for _, currentRecord := range currentRecords {
		oldRecord, exists := previousRecords[currentRecord.Hash]

		if !exists {
			// New record
			changeType := ChangeNewRecord
			if currentRecord.Type == "A" || currentRecord.Type == "AAAA" {
				changeType = ChangeIPAddress
			} else if currentRecord.Type == "TXT" {
				changeType = ChangeTXTRecord
			} else if currentRecord.Type == "CNAME" {
				changeType = ChangeCNAMERecord
			}

			changes = append(changes, ChangeResult{
				Type:        changeType,
				Domain:      domain,
				Record:      currentRecord,
				Description: fmt.Sprintf("New %s record: %s -> %s", currentRecord.Type, currentRecord.Name, currentRecord.Data),
				Timestamp:   now,
			})
		} else if d.hasRecordChanged(oldRecord, currentRecord) {
			// Modified record
			changeType := ChangeModifiedRecord
			if currentRecord.Type == "A" || currentRecord.Type == "AAAA" {
				changeType = ChangeIPAddress
			} else if currentRecord.Type == "TXT" {
				changeType = ChangeTXTRecord
			} else if currentRecord.Type == "CNAME" {
				changeType = ChangeCNAMERecord
			}

			changes = append(changes, ChangeResult{
				Type:        changeType,
				Domain:      domain,
				Record:      currentRecord,
				OldRecord:   &oldRecord,
				Description: d.getChangeDescription(oldRecord, currentRecord),
				Timestamp:   now,
			})
		}
	}

	// Update cache
	d.recordCache[domain] = make(map[string]DNSRecord)
	for _, record := range currentRecords {
		d.recordCache[domain][record.Hash] = record
	}
	d.lastHashes[domain] = currentHash

	return changes, nil
}

// hasRecordChanged checks if a record has meaningful changes
func (d *DigitalOceanClient) hasRecordChanged(old, new DNSRecord) bool {
	if old.Data != new.Data {
		return true
	}
	if old.TTL != new.TTL {
		return true
	}
	if old.Priority != new.Priority && old.Type == "MX" {
		return true
	}
	if old.Port != new.Port && old.Type == "SRV" {
		return true
	}
	return false
}

// getChangeDescription generates a descriptive message for record changes
func (d *DigitalOceanClient) getChangeDescription(old, new DNSRecord) string {
	switch {
	case old.Data != new.Data:
		return fmt.Sprintf("%s record changed: %s -> %s (was: %s)", 
			new.Type, new.Name, new.Data, old.Data)
	case old.TTL != new.TTL:
		return fmt.Sprintf("%s record TTL changed: %s -> %d (was: %d)", 
			new.Type, new.Name, new.TTL, old.TTL)
	case old.Priority != new.Priority:
		return fmt.Sprintf("MX record priority changed: %s -> %d (was: %d)", 
			new.Name, new.Priority, old.Priority)
	default:
		return fmt.Sprintf("%s record modified: %s", new.Type, new.Name)
	}
}

// generateLogs creates log entries from current records and changes
func (d *DigitalOceanClient) generateLogs(domain string, records []DNSRecord, changes []ChangeResult) []string {
	var logs []string
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// Add change detection header
	if len(changes) > 0 {
		changeHeader := fmt.Sprintf("%s [CHANGE] Detected %d changes for %s", 
			timestamp, len(changes), domain)
		logs = append(logs, changeHeader)
	}

	// Add change details
	for _, change := range changes {
		changeLog := fmt.Sprintf("%s [DETECTION] %s", timestamp, change.Description)
		
		// Add specific details for critical changes
		if change.Type == ChangeIPAddress && change.OldRecord != nil {
			changeLog += fmt.Sprintf(" | IP change detected: %s -> %s", 
				change.OldRecord.Data, change.Record.Data)
		}
		if change.Type == ChangeTXTRecord && change.OldRecord != nil {
			changeLog += " | TXT record modified (possible SPF/DKIM/DMARC change)"
		}
		
		logs = append(logs, changeLog)
	}

	// Add current state summary
	if len(records) > 0 {
		summary := fmt.Sprintf("%s [STATE] %d records current for %s", 
			timestamp, len(records), domain)
		logs = append(logs, summary)
	}

	return logs
}

// calculateDomainHash creates a hash of all records for quick change detection
func (d *DigitalOceanClient) calculateDomainHash(records []DNSRecord) string {
	// Sort records for consistent hashing
	sort.Slice(records, func(i, j int) bool {
		return records[i].ID < records[j].ID
	})

	var sb strings.Builder
	for _, record := range records {
		sb.WriteString(fmt.Sprintf("%d|%s|%s|%s|%d|%d|", 
			record.ID, record.Type, record.Name, record.Data, record.TTL, record.Priority))
	}

	hash := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(hash[:])
}

// getCurrentDNSRecords fetches and processes current DNS records
func (d *DigitalOceanClient) getCurrentDNSRecords(domain string) ([]DNSRecord, error) {
	url := fmt.Sprintf("https://api.digitalocean.com/v2/domains/%s/records", domain)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+d.cfg.APIKeys.DigitalOcean)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	var result struct {
		DomainRecords []DNSRecord `json:"domain_records"`
		Meta          struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}
	
	// Calculate hashes for each record
	for i := range result.DomainRecords {
		record := &result.DomainRecords[i]
		record.Hash = d.calculateRecordHash(*record)
	}
	
	return result.DomainRecords, nil
}

// calculateRecordHash creates a unique hash for a single record
func (d *DigitalOceanClient) calculateRecordHash(record DNSRecord) string {
	data := fmt.Sprintf("%d|%s|%s|%s|%d|%d|%d|%d|", 
		record.ID, record.Type, record.Name, record.Data, 
		record.TTL, record.Priority, record.Port, record.Weight)
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // First 16 chars for efficiency
}

// GetDomainInfo retrieves information about a DigitalOcean domain
func (d *DigitalOceanClient) GetDomainInfo(domain string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.digitalocean.com/v2/domains/%s", domain)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+d.cfg.APIKeys.DigitalOcean)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status: %d", resp.StatusCode)
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}
	
	return result, nil
}

// TestConnection tests the DigitalOcean API connection
func (d *DigitalOceanClient) TestConnection() error {
	if d.cfg.APIKeys.DigitalOcean == "" {
		return fmt.Errorf("DigitalOcean API key not configured")
	}
	
	url := "https://api.digitalocean.com/v2/account"
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %v", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+d.cfg.APIKeys.DigitalOcean)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("test request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("test failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	return nil
}

// IsConfigured checks if DigitalOcean is properly configured
func (d *DigitalOceanClient) IsConfigured() bool {
	return d.cfg.APIKeys.DigitalOcean != "" && len(d.cfg.DigitalOcean.Domains) > 0
}

// GetDomains returns the list of configured DigitalOcean domains
func (d *DigitalOceanClient) GetDomains() []string {
	return d.cfg.DigitalOcean.Domains
}

// ClearCache clears the change detection cache for a domain
func (d *DigitalOceanClient) ClearCache(domain string) {
	delete(d.recordCache, domain)
	delete(d.lastHashes, domain)
}

// GetChangeStats returns statistics about detected changes
func (d *DigitalOceanClient) GetChangeStats(domain string) map[string]int {
	stats := map[string]int{
		"total_records":    len(d.recordCache[domain]),
		"last_check":       int(time.Since(d.lastFetch).Seconds()),
		"domain_hash":      len(d.lastHashes[domain]),
	}
	return stats
}