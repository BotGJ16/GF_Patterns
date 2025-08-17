# 📖 Usage Guide

Comprehensive guide for using **GF Patterns** - Elite security testing patterns.

---

## 🎯 Quick Start

### Basic Pattern Usage
```bash
# Find XSS vulnerabilities
cat urls.txt | gf xss > xss_findings.txt

# Find SQL injection
cat urls.txt | gf sqli > sqli_findings.txt

# Find SSRF vulnerabilities
cat urls.txt | gf ssrf > ssrf_findings.txt
```

---

## 🔍 Pattern Categories

### 1. Web Application Patterns
| Pattern | Description | Usage |
|---------|-------------|--------|
| `xss` | Cross-Site Scripting | `gf xss` |
| `sqli` | SQL Injection | `gf sqli` |
| `ssrf` | Server-Side Request Forgery | `gf ssrf` |
| `idor` | Insecure Direct Object Reference | `gf idor` |
| `lfi` | Local File Inclusion | `gf lfi` |
| `ssti` | Server-Side Template Injection | `gf ssti` |
| `xxe` | XML External Entity | `gf xxe` |
| `nosql` | NoSQL Injection | `gf nosql` |

### 2. Infrastructure Patterns
| Pattern | Description | Usage |
|---------|-------------|--------|
| `privilege_escalation` | Privilege escalation vectors | `gf privilege_escalation` |
| `lateral_movement` | Lateral movement techniques | `gf lateral_movement` |
| `persistence` | Persistence mechanisms | `gf persistence` |
| `supply_chain` | Supply chain attacks | `gf supply_chain` |

### 3. Cloud Security Patterns
| Pattern | Description | Usage |
|---------|-------------|--------|
| `container_escape` | Container escape vectors | `gf container_escape` |
| `cloud_misconfig` | Cloud misconfigurations | `gf cloud_misconfig` |
| `api_abuse` | API abuse patterns | `gf api_abuse` |

### 4. Web3/Crypto Patterns
| Pattern | Description | Usage |
|---------|-------------|--------|
| `smartcontract_vuln` | Smart contract vulnerabilities | `gf smartcontract_vuln` |
| `wallet_leaks` | Wallet private key leaks | `gf wallet_leaks` |
| `defi_exploits` | DeFi protocol exploits | `gf defi_exploits` |

---

## 🚀 Advanced Usage

### Pattern Combinations
```bash
# Find high-risk vulnerabilities
cat urls.txt | gf xss sqli ssrf > critical_findings.txt

# Web3 focused scan
cat urls.txt | gf smartcontract_vuln wallet_leaks defi_exploits > web3_findings.txt

# Cloud security assessment
cat urls.txt | gf cloud_misconfig container_escape api_abuse > cloud_findings.txt
```

### With Recon Tools
```bash
# Full reconnaissance workflow
subfinder -d target.com | httpx | gf xss > xss_targets.txt
subfinder -d target.com | httpx | gf sqli > sqli_targets.txt
```

### Mass Scanning
```bash
# Scan multiple domains
for domain in $(cat domains.txt); do
    echo "[*] Scanning $domain"
    subfinder -d $domain | httpx | gf xss > "${domain}_xss.txt"
done
```

---

## 📊 Output Formats

### JSON Output
```bash
# Structured JSON output
cat urls.txt | gf xss | jq -R '{url: ., pattern: "xss", timestamp: now}' > findings.json
```

### CSV Output
```bash
# CSV format for analysis
cat urls.txt | gf sqli | awk '{print $0",sqli,"strftime()}' > findings.csv
```

---

## 🔄 Integration Examples

### With Burp Suite
```bash
# Export from Burp and scan
cat burp_urls.txt | gf xss > burp_xss.txt
```

### With OWASP ZAP
```bash
# ZAP automation
zap-cli urls | gf sqli > zap_sqli.txt
```

### With Nuclei
```bash
# Combine with nuclei
cat urls.txt | gf ssrf | nuclei -t ssrf-templates/
```

---

## 🎯 Targeted Scanning

### Single Pattern Deep Dive
```bash
# Focus on specific vulnerability
cat urls.txt | gf xss | while read url; do
    echo "[*] Testing: $url"
    # Add your custom testing logic here
done
```

### Parameter Analysis
```bash
# Extract parameters for testing
cat urls.txt | gf xss | grep -oE '[?&][^=]+=' | sort -u > parameters.txt
```

---

## 📈 Performance Optimization

### Parallel Processing
```bash
# Use GNU parallel for speed
cat urls.txt | parallel -j 10 'echo {} | gf xss' > xss_parallel.txt
```

### Memory Efficient
```bash
# Process large files efficiently
cat large_urls.txt | gf xss | head -1000 > sample_xss.txt
```

---

## 🛠️ Custom Patterns

### Creating Custom Patterns
```bash
# Create new pattern
cat > ~/.gf/custom_vuln.json << 'EOF'
{
    "flags": "-HanrE",
    "pattern": "custom_vulnerability_pattern"
}
EOF

# Test custom pattern
echo "test" | gf custom_vuln
```

### Pattern Validation
```bash
# Validate patterns work
gf -list | xargs -I {} sh -c 'echo "Testing {}"; echo "test" | gf {}'
```

---

## 🎨 Visualization

### Generate Reports
```bash
# Create HTML report
cat findings.txt | gf xss | awk '
BEGIN {print "<html><body><h1>XSS Findings</h1><ul>"}
{print "<li>" $0 "</li>"}
END {print "</ul></body></html>"}
' > report.html
```

### Charts and Graphs
```bash
# Generate statistics
gf -list | wc -l > total_patterns.txt
cat findings.txt | grep -oE 'gf [^ ]+' | sort | uniq -c > pattern_stats.txt
```

---

## 🔍 Troubleshooting

### Debug Mode
```bash
# Enable debug output
set -x
cat urls.txt | gf xss
set +x
```

### Pattern Testing
```bash
# Test specific pattern
echo "https://example.com/test?xss=<script>" | gf xss
```

### Performance Issues
```bash
# Monitor resource usage
time cat urls.txt | gf xss
```

---

## 📚 Examples

### Real-World Scenarios

#### Bug Bounty Hunting
```bash
# Target specific program
subfinder -d target.com | httpx | gf xss sqli ssrf > bounty_findings.txt
```

#### Red Team Assessment
```bash
# Comprehensive assessment
./scripts/ultimate_hunt.sh client.com
```

#### Security Research
```bash
# Research new patterns
cat research_urls.txt | gf all_patterns > research_findings.txt
```

---

## 🎓 Learning Resources

### Pattern Documentation
```bash
# Get pattern info
gf -list | xargs -I {} sh -c 'echo "=== {} ==="; gf -help {} 2>/dev/null || echo "No help available"'
```

### Community Examples
- [GitHub Examples](https://github.com/tt860480-netizen/GF_Patterns/tree/main/examples)
- [Video Tutorials](https://youtube.com/gf-patterns-tutorials)
- [Discord Community](https://discord.gg/gf-patterns)

---

## 🚀 Next Steps

### Advanced Techniques
1. **Custom Automation**: Create your own scanning scripts
2. **Integration**: Connect with your existing security tools
3. **Contributing**: Add new patterns to the collection

### Professional Usage
1. **Enterprise Deployment**: Scale for large organizations
2. **CI/CD Integration**: Automated security testing
3. **Custom Reporting**: Generate client-ready reports

---

<div align="center">

**🎯 Ready to hunt vulnerabilities like a pro!**

**📖 Check out our [Installation Guide](INSTALLATION.md) to get started!**

</div>