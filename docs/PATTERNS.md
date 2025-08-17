# 🎯 Pattern Documentation

Complete documentation for all **GF Patterns** - Elite security testing patterns.

---

## 🏗️ Pattern Structure

Each pattern follows this structure:
```json
{
    "flags": "-HanrE",
    "pattern": "regex_pattern",
    "description": "What this pattern detects",
    "severity": "HIGH|MEDIUM|LOW",
    "category": "vulnerability_type"
}
```

---

## 🔍 Web Application Patterns

### XSS (Cross-Site Scripting)
**File**: `xss.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(<script[^>]*>.*?</script>|<[^>]+on\\w+\\s*=|javascript:|data:text/html|vbscript:|livescript:|mocha:|<iframe|<object|<embed|<form|<input|<svg|<math)",
    "description": "Detects XSS vectors in URLs and parameters",
    "severity": "HIGH",
    "category": "xss"
}
```

**Usage**:
```bash
cat urls.txt | gf xss
```

**Examples**:
- `https://example.com/search?q=<script>alert(1)</script>`
- `https://example.com/page?callback=javascript:alert(1)`
- `https://example.com/data:text/html,<script>alert(1)</script>`

---

### SQL Injection
**File**: `sqli.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(union\\s+select|sleep\\(|benchmark\\(|pg_sleep\\(|waitfor\\s+delay|';\\s*--|\";\\s*--|\\b(select|insert|update|delete|drop|alter|create)\\s+(\\*|from|into|table|database))",
    "description": "Detects SQL injection attempts",
    "severity": "HIGH",
    "category": "sqli"
}
```

**Usage**:
```bash
cat urls.txt | gf sqli
```

**Examples**:
- `https://example.com/user?id=1' OR '1'='1`
- `https://example.com/search?q=' UNION SELECT * FROM users--`
- `https://example.com/page?id=1; DROP TABLE users--`

---

### SSRF (Server-Side Request Forgery)
**File**: `ssrf.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(file://|dict://|sftp://|ldap://|tftp://|gopher://|http://169\\.254\\.169\\.254|http://metadata\\.google|http://localhost|http://127\\.0\\.0\\.1|http://0\\.0\\.0\\.0|http://[::1]|http://0000)",
    "description": "Detects SSRF attack vectors",
    "severity": "HIGH",
    "category": "ssrf"
}
```

**Usage**:
```bash
cat urls.txt | gf ssrf
```

**Examples**:
- `https://example.com/redirect?url=file:///etc/passwd`
- `https://example.com/webhook?url=http://169.254.169.254/latest/meta-data/`
- `https://example.com/proxy?target=http://localhost:22`

---

### IDOR (Insecure Direct Object Reference)
**File**: `idor.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(id=\\d+|user=\\d+|account=\\d+|profile=\\d+|file=.*\\.pdf|document=.*\\.doc|order=\\d+|invoice=\\d+|report=\\d+)",
    "description": "Detects potential IDOR vulnerabilities",
    "severity": "MEDIUM",
    "category": "idor"
}
```

**Usage**:
```bash
cat urls.txt | gf idor
```

**Examples**:
- `https://example.com/user?id=12345`
- `https://example.com/download?file=../etc/passwd`
- `https://example.com/invoice?order=1001`

---

### LFI (Local File Inclusion)
**File**: `lfi.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(\\.\\./|\\.\\.\\\\|/etc/passwd|/etc/hosts|/proc/self/environ|/var/log/|windows/system32/|boot\\.ini|win\\.ini)",
    "description": "Detects local file inclusion attempts",
    "severity": "HIGH",
    "category": "lfi"
}
```

**Usage**:
```bash
cat urls.txt | gf lfi
```

**Examples**:
- `https://example.com/page?file=../../../etc/passwd`
- `https://example.com/download?path=../../../../windows/system32/config/sam`
- `https://example.com/include?file=/proc/self/environ`

---

### SSTI (Server-Side Template Injection)
**File**: `ssti.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(\\{\\{.*\\}\\}|\\{\\%.*\\%\\}|\\$\\{.*\\}|\\#\\{.*\\}|\\{\\{.*\\|.*\\}\\}|\\{\\{.*\\..*\\}\\}|\\{\\{.*\\[.*\\]\\}\\})",
    "description": "Detects server-side template injection vectors",
    "severity": "HIGH",
    "category": "ssti"
}
```

**Usage**:
```bash
cat urls.txt | gf ssti
```

**Examples**:
- `https://example.com/page?name={{7*7}}`
- `https://example.com/template?content={{config}}`
- `https://example.com/greeting?user={{self.__init__.__globals__}}`

---

### XXE (XML External Entity)
**File**: `xxe.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(<!ENTITY|<!DOCTYPE|SYSTEM\\s+[\"']|file://|http://|ftp://|php://filter|expect://|data://)",
    "description": "Detects XML external entity injection",
    "severity": "HIGH",
    "category": "xxe"
}
```

**Usage**:
```bash
cat urls.txt | gf xxe
```

**Examples**:
- `https://example.com/xml?data=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- `https://example.com/upload?xml=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>`

---

### NoSQL Injection
**File**: `nosql.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(\\$ne|\\$gt|\\$lt|\\$regex|\\$where|\\$exists|\\$nin|\\$in|\\$or|\\$and|\\$not|\\$elemMatch|\\$all|\\$size|\\$slice)",
    "description": "Detects NoSQL injection attempts",
    "severity": "HIGH",
    "category": "nosql"
}
```

**Usage**:
```bash
cat urls.txt | gf nosql
```

**Examples**:
- `https://example.com/api/users?username[$ne]=admin`
- `https://example.com/search?q[$regex]=.*`
- `https://example.com/users?age[$gt]=0`

---

## 🏢 Infrastructure Patterns

### Privilege Escalation
**File**: `privilege_escalation.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(sudo|admin|root|administrator|SYSTEM|NT AUTHORITY|LocalSystem|wheel|docker|lxd|kubernetes|cluster-admin)",
    "description": "Detects privilege escalation vectors",
    "severity": "HIGH",
    "category": "privilege_escalation"
}
```

**Usage**:
```bash
cat logs.txt | gf privilege_escalation
```

---

### Lateral Movement
**File**: `lateral_movement.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(\\\\[a-zA-Z0-9.-]+\\[\\w\\$]|\\\\\\\\[a-zA-Z0-9.-]+\\\\|wmic|psexec|winrm|ssh|rdp|mstsc|net use|net session)",
    "description": "Detects lateral movement indicators",
    "severity": "HIGH",
    "category": "lateral_movement"
}
```

**Usage**:
```bash
cat logs.txt | gf lateral_movement
```

---

### Persistence
**File**: `persistence.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(registry|startup|scheduled tasks|services|run keys|init.d|systemd|crontab|login scripts|WMI|bitsadmin)",
    "description": "Detects persistence mechanisms",
    "severity": "MEDIUM",
    "category": "persistence"
}
```

**Usage**:
```bash
cat logs.txt | gf persistence
```

---

## ☁️ Cloud Security Patterns

### Container Escape
**File**: `container_escape.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(docker.sock|/var/run/docker.sock|containerd.sock|/run/containerd/containerd.sock|privileged|cap_add|hostPID|hostNetwork|hostIPC|--privileged|--cap-add)",
    "description": "Detects container escape vectors",
    "severity": "HIGH",
    "category": "container_escape"
}
```

**Usage**:
```bash
cat configs.txt | gf container_escape
```

---

### Cloud Misconfiguration
**File**: `cloud_misconfig.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(public-read|public-write|authenticated-read|bucket-owner-read|bucket-owner-full-control|aws_access_key_id|aws_secret_access_key|AKIA|ASIA|arn:aws|s3://|gs://|azure-blob)",
    "description": "Detects cloud misconfigurations",
    "severity": "MEDIUM",
    "category": "cloud_misconfig"
}
```

**Usage**:
```bash
cat configs.txt | gf cloud_misconfig
```

---

### API Abuse
**File**: `api_abuse.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(api_key|apikey|token|bearer|jwt|oauth|secret|password|admin|root|debug|test|dev|staging)",
    "description": "Detects API abuse patterns",
    "severity": "MEDIUM",
    "category": "api_abuse"
}
```

**Usage**:
```bash
cat api_logs.txt | gf api_abuse
```

---

## 🔗 Web3/Crypto Patterns

### Smart Contract Vulnerabilities
**File**: `smartcontract_vuln.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(reentrancy|overflow|underflow|delegatecall|selfdestruct|tx.origin|block.timestamp|block.number|now|gasleft|call.value|send|transfer)",
    "description": "Detects smart contract vulnerabilities",
    "severity": "HIGH",
    "category": "smartcontract_vuln"
}
```

**Usage**:
```bash
cat contracts.txt | gf smartcontract_vuln
```

---

### Wallet Leaks
**File**: `wallet_leaks.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(0x[a-fA-F0-9]{40}|0x[a-fA-F0-9]{64}|private_key|mnemonic|seed phrase|keystore|wallet.dat|UTC--|0x[a-fA-F0-9]{64})",
    "description": "Detects wallet private key leaks",
    "severity": "CRITICAL",
    "category": "wallet_leaks"
}
```

**Usage**:
```bash
cat source_code.txt | gf wallet_leaks
```

---

### DeFi Exploits
**File**: `defi_exploits.json`
```json
{
    "flags": "-HanrE",
    "pattern": "(flashloan|flash loan|price oracle|oracle manipulation|slippage|impermanent loss|liquidity pool|yield farming|governance token|staking|vault)",
    "description": "Detects DeFi protocol exploits",
    "severity": "HIGH",
    "category": "defi_exploits"
}
```

**Usage**:
```bash
cat defi_code.txt | gf defi_exploits
```

---

## 🎯 Custom Pattern Creation

### Basic Structure
```json
{
    "flags": "-HanrE",
    "pattern": "your_regex_pattern_here",
    "description": "Description of what this pattern detects",
    "severity": "HIGH|MEDIUM|LOW",
    "category": "vulnerability_category"
}
```

### Example Custom Pattern
```json
{
    "flags": "-HanrE",
    "pattern": "(custom_vuln_pattern|another_pattern)",
    "description": "Detects custom vulnerability in your application",
    "severity": "HIGH",
    "category": "custom"
}
```

---

## 📊 Pattern Testing

### Test Your Patterns
```bash
# Test against sample data
echo "https://example.com/test?xss=<script>" | gf xss

# Test all patterns
gf -list | while read pattern; do
    echo "Testing $pattern"
    cat test_data.txt | gf "$pattern" > "test_${pattern}.txt"
done
```

### Validate Patterns
```bash
# Check pattern syntax
gf -help xss

# List all patterns
gf -list
```

---

## 🎓 Learning Resources

### Pattern Development
- [Regex Tutorial](https://regex101.com/)
- [GF Tool Documentation](https://github.com/tomnomnom/gf)
- [Security Pattern Examples](https://github.com/1ndianl33t/Gf-Patterns)

### Vulnerability Research
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)

---

<div align="center">

**🎯 Master these patterns to become a security testing expert!**

**📚 Check out our [Usage Guide](USAGE.md) for practical examples!**

</div>