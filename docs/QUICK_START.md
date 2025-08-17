# ⚡ Quick Start Guide

Get started with **GF Patterns** in under 5 minutes!

---

## 🚀 5-Minute Setup

### 1. Install Everything
```bash
# One-line installation
curl -sSL https://raw.githubusercontent.com/your-repo/Gf-Patterns/main/install.sh | bash
```

### 2. Verify Installation
```bash
# Quick verification
./verify-installation.sh
```

### 3. Start Testing
```bash
# Test on a target
echo "https://example.com" | ./ultimate_hunt.sh
```

---

## 🎯 Your First Scan

### Basic Usage
```bash
# Single URL scan
echo "https://target.com" | ./ultimate_hunt.sh

# Multiple URLs
cat targets.txt | ./ultimate_hunt.sh

# With specific patterns
echo "https://target.com" | gf xss
```

### Real Example
```bash
# 1. Find subdomains
subfinder -d target.com | tee subdomains.txt

# 2. Get URLs
cat subdomains.txt | gau | tee urls.txt

# 3. Find vulnerabilities
cat urls.txt | ./ultimate_hunt.sh
```

---

## 📊 Understanding Results

### Output Structure
```
results/
├── target.com/
│   ├── xss.txt          # XSS vulnerabilities
│   ├── sqli.txt         # SQL injection
│   ├── ssrf.txt         # SSRF vulnerabilities
│   ├── lfi.txt          # Local file inclusion
│   └── open_redirect.txt # Open redirects
```

### Sample Results
```
[+] XSS Found: https://target.com/search?q=<script>alert(1)</script>
[+] SQLi Found: https://target.com/page?id=1' OR 1=1--
[+] SSRF Found: https://target.com/api?url=http://169.254.169.254
```

---

## 🔍 Common Patterns

### XSS Testing
```bash
# Find XSS vulnerabilities
echo "https://target.com" | gf xss

# Test with payloads
echo "https://target.com/search?q=" | gf xss | xargs -I {} echo "{}<script>alert(1)</script>"
```

### SQL Injection
```bash
# Find SQLi vulnerabilities
echo "https://target.com" | gf sqli

# Test with payloads
echo "https://target.com/page?id=1" | gf sqli | xargs -I {} echo "{}' OR 1=1--"
```

### SSRF Testing
```bash
# Find SSRF vulnerabilities
echo "https://target.com" | gf ssrf

# Test with payloads
echo "https://target.com/api?url=" | gf ssrf | xargs -I {} echo "{}http://169.254.169.254"
```

---

## 🛠️ Pro Tips

### 1. Combine Tools
```bash
# Full reconnaissance pipeline
subfinder -d target.com | httpx | gau | ./ultimate_hunt.sh
```

### 2. Filter Results
```bash
# Only show high-confidence results
cat results.txt | grep -E "\[CRITICAL\]|\[HIGH\]"
```

### 3. Save Everything
```bash
# Save all results
./ultimate_hunt.sh target.com | tee full_scan_results.txt
```

---

## 🎓 Learning Path

### Beginner (Day 1-3)
- [ ] Install GF Patterns
- [ ] Run first scan
- [ ] Understand basic patterns
- [ ] Practice on test targets

### Intermediate (Week 1-2)
- [ ] Master all 58 patterns
- [ ] Learn tool combinations
- [ ] Create custom patterns
- [ ] Automate workflows

### Advanced (Month 1+)
- [ ] Build custom tools
- [ ] Contribute patterns
- [ ] Mentor others
- [ ] Research new vulnerabilities

---

## 📚 Next Steps

### Read These Guides
1. **[Security Testing Guide](SECURITY_TESTING.md)** - Deep dive into testing
2. **[Pattern Documentation](PATTERNS.md)** - All 58 patterns explained
3. **[Contributing Guide](CONTRIBUTING.md)** - How to contribute

### Join Community
- **Discord**: [Join our Discord](https://discord.gg/gf-patterns)
- **GitHub**: [Star & Watch](https://github.com/your-repo/Gf-Patterns)
- **Twitter**: [@GFPatterns](https://twitter.com/GFPatterns)

---

## 🆘 Need Help?

### Quick Help
```bash
# Check if everything works
./verify-installation.sh

# Get help
./ultimate_hunt.sh --help

# Check patterns
gf -list
```

### Common Issues
- **"command not found"** → Add Go bin to PATH
- **"permission denied"** → Run `chmod +x scripts/*`
- **"no results"** → Check target accessibility

---

<div align="center">

**🎉 You're ready to hunt vulnerabilities!**

**🚀 Start with: `echo "https://example.com" | ./ultimate_hunt.sh`**

</div>