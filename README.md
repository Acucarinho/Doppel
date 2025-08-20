# Doppel <img src="https://raw.githubusercontent.com/Acucarinho/Doppel/main/logo/Doppel.png" width="40"/>

[![GitHub release](https://img.shields.io/badge/release-v0.3.0-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**Doppel** is a Red Team oriented DNS telemetry tool that helps operators detect when Blue Teams, IDS, or IPS systems are performing reverse lookups or other DNS-based reconnaissance on attacker-controlled infrastructure. It centralizes multiple DNS log sources, performs pattern-based detection, and provides reputation enrichment and alerting.

---

## Features

- ✅ **Real-time DNS monitoring**  
- ✅ **Advanced threat detection with VirusTotal integration**  
- ✅ **Advanced reverse lookup detection with multiple patterns**  
- ✅ **IP address extraction and validation**  
- ✅ **Comprehensive tracking of detected IPs**  
- ✅ **Batch IP reputation checking**  
- ✅ **Fast-Flux for IP rotation**  
- ✅ **Support for Cloudflare, AWS Route53 and DigitalOcean**

---

## Notes

- **Note:** For Route53 logs, you need to enable Resolver Query Logs and configure an S3 bucket or CloudWatch Logs.  
- **Note:** DigitalOcean doesn't offer logs, but rather records, so Doppel only detects suspicious changes using DigitalOcean logs.

---

## Quickstart

### Build (Go)

```bash
# from repository root
go build -o bin/doppel ./cmd/rdns-telemetry
```
