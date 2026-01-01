# CapXray - Changelog

## [v1.1.0] - 2026-01-01

### 🎉 Major Features

#### JA3 TLS Fingerprinting

- Full JA3 hash computation from TLS Client Hello
- Database of known malicious fingerprints (Trickbot, Dridex, Metasploit, Cobalt Strike)
- Automatic threat detection based on TLS characteristics

#### ML-Based Anomaly Detection

- Statistical beaconing detection using coefficient of variation
- Data exfiltration pattern identification
- Packet size anomaly detection
- Behavioral analysis without signature dependencies

#### Real-Time Web Dashboard

- Modern HTML/CSS/JavaScript interface
- REST API with CORS support
- Live metrics updated every 3 seconds
- Protocol distribution visualization
- Alert severity color coding
- Responsive design for all devices

### 🔧 Improvements

- Enhanced CLI output with color coding
- Improved error handling across all modules
- Optimized flow reconstruction performance
- Better memory management in worker pools

### 📝 Documentation

- Comprehensive README with examples
- MIT License added
- Detailed walkthrough document
- Architecture diagrams with Mermaid

---

## [v1.0.0] - 2026-01-01

### Initial Release

#### Core Features

- PCAP file loading and parsing
- Flow reconstruction (TCP/UDP/ICMP)
- Protocol analysis (DNS, HTTP, TLS)
- Threat detection (DNS tunneling, suspicious UAs)
- CLI commands: scan, stats, flows, detect, export
- YAML-based rule configuration
- JSON export for SIEM integration
- Premium CLI UX with ASCII banner and colors

#### Analyzers

- DNS analyzer (length, entropy, NXDOMAIN)
- HTTP analyzer (User-Agent, credentials)
- TLS analyzer (basic handshake inspection)
- Statistics analyzer (protocol distribution)

#### Detection

- DNS tunneling (entropy-based)
- Port scanning (skeleton)
- Beaconing (pattern-based)

### 📦 Dependencies

- google/gopacket
- spf13/cobra
- fatih/color
- olekukonko/tablewriter
- gopkg.in/yaml.v3
