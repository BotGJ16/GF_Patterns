# 🤝 Contributing to GF Patterns

Thank you for your interest in contributing to **GF Patterns**! This guide will help you contribute effectively to our elite security pattern collection.

---

## 🎯 Contribution Types

### 🆕 New Patterns
- **Security patterns** for new attack vectors
- **Enhanced patterns** for existing vulnerabilities
- **Specialized patterns** for niche technologies

### 🔧 Improvements
- **Pattern optimization** for better accuracy
- **Performance enhancements** for faster matching
- **Documentation improvements** and examples

### 🐛 Bug Fixes
- **False positive** reduction
- **Pattern corrections** and edge cases
- **Compatibility fixes** for different tools

---

## 📋 Before You Start

### ✅ Prerequisites
- [ ] Basic understanding of security vulnerabilities
- [ ] Familiarity with JSON format
- [ ] Testing environment setup
- [ ] Git and GitHub knowledge

### 🎯 Pattern Categories
Review our existing categories:
- **Web Application** (XSS, SQLi, SSRF, etc.)
- **Infrastructure** (Privilege escalation, Lateral movement)
- **Cloud Security** (Container escape, Misconfigurations)
- **Web3/Crypto** (Smart contracts, DeFi exploits)
- **Specialized** (IoT, Mobile, Zero-days)

---

## 🚀 Quick Start Guide

### 1. Fork & Clone
```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/GF_Patterns.git
cd GF_Patterns
```

### 2. Create Branch
```bash
git checkout -b feature/new-pattern-name
# or
git checkout -b fix/pattern-correction
```

### 3. Setup Development Environment
```bash
# Install required tools
go install github.com/tomnomnom/gf@latest

# Test your setup
gf -list
```

---

## 📝 Pattern Creation Guidelines

### 📊 JSON Structure Template
```json
{
  "pattern": "your_pattern_name",
  "description": "Clear description of what this pattern detects",
  "category": "web-application|infrastructure|cloud-security|web3-crypto|specialized",
  "severity": "critical|high|medium|low",
  "tags": ["xss", "reflected", "stored", "dom-based"],
  "examples": [
    {
      "vulnerable": "example.com/search?q=<script>alert(1)</script>",
      "description": "Reflected XSS in search parameter"
    }
  ],
  "references": [
    "https://owasp.org/www-community/attacks/xss/",
    "https://portswigger.net/web-security/cross-site-scripting"
  ],
  "test_cases": [
    {
      "input": "example.com/page?id=1",
      "expected": "should match if vulnerable"
    }
  ]
}
```

### 🎯 Pattern Naming Convention
- **Use lowercase** with underscores
- **Be descriptive** but concise
- **Include context** when needed
- **Examples**:
  - `xss_reflected_parameters`
  - `sqli_error_based_mysql`
  - `ssrf_url_parameters`
  - `jwt_none_algorithm`

---

## 🔍 Pattern Testing

### ✅ Testing Checklist
- [ ] **Valid vulnerabilities** should match
- [ ] **False positives** should be minimized
- [ ] **Edge cases** are handled
- [ ] **Performance** is acceptable
- [ ] **Documentation** is complete

### 🧪 Testing Commands
```bash
# Test individual pattern
echo "test-url.com/param=value" | gf your_pattern_name

# Test against real targets (authorized only)
cat test_urls.txt | gf your_pattern_name > results.txt

# Validate results
wc -l results.txt  # Check match count
head results.txt   # Review matches
```

### 📊 Performance Testing
```bash
# Test with large datasets
time cat large_urls.txt | gf your_pattern_name > /dev/null

# Memory usage check
/usr/bin/time -v cat large_urls.txt | gf your_pattern_name
```

---

### Required Files
- **Pattern file** (`your_pattern.json`)
- **Documentation** (README updates)
- **Test cases** (examples and edge cases)

---

## 🎯 Quality Standards

### 🔍 Accuracy Requirements
- **< 5% false positive rate**
- **> 95% true positive rate**
- **Comprehensive edge case coverage**
- **Clear vulnerability identification**

### 📏 Performance Standards
- **Fast matching** (< 1ms per URL)
- **Memory efficient** (< 1MB additional)
- **Scalable** (handles 1M+ URLs)

### 📝 Documentation Standards
- **Clear descriptions**
- **Practical examples**
- **Reference links**
- **Testing instructions**

---

## 🔄 Submission Process

### 1. Create Pattern
```bash
# Create pattern file
touch category/your_pattern.json

# Add your pattern content
# Follow the JSON template
```

### 2. Test Thoroughly
```bash
# Run comprehensive tests
./scripts/test_pattern.sh your_pattern.json

# Validate against test cases
./scripts/validate_pattern.py your_pattern.json
```

### 3. Update Documentation
```bash
# Update README.md if needed
# Add your pattern to relevant sections
```

### 4. Submit Pull Request
```bash
git add .
git commit -m "Add new pattern: your_pattern_name"
git push origin feature/your-pattern-name
```

---

## 📋 Pull Request Template

### Title Format
```
Add: [Pattern Name] - [Brief Description]
Fix: [Pattern Name] - [Issue Description]
Update: [Pattern Name] - [Enhancement Description]
```

### Description Template
```markdown
## 🎯 What
[Brief description of changes]

## 🔍 Why
[Reason for the change]

## ✅ Testing
- [ ] Tested against real targets
- [ ] False positive rate < 5%
- [ ] Performance benchmarks passed
- [ ] Documentation updated

## 📊 Results
- True positives: X/100
- False positives: Y/1000
- Performance: Z ms per URL

## 🔗 References
[Relevant security resources]
```

---

## 🐛 Reporting Issues

### Bug Report Template
```markdown
**Pattern Name:** [Affected pattern]
**Issue Type:** [False positive/False negative/Performance]
**Description:** [Clear description]
**Example URL:** [If applicable]
**Expected Behavior:** [What should happen]
**Actual Behavior:** [What actually happens]
**Environment:** [OS, tools, versions]
```

### Security Issues
For security-related issues:
- **Use GitHub Security Advisories**
- **Provide detailed reproduction steps**

---

## 🎨 Style Guide

### JSON Formatting
- **2 spaces** for indentation
- **Alphabetical order** for keys
- **Consistent quotes** (double quotes)
- **Trailing commas** avoided

### Documentation Style
- **Clear, concise language**
- **Practical examples**
- **Consistent terminology**
- **Proper markdown formatting**

---

## 🏆 Recognition

### Contributor Levels
- **🥉 Bronze**: 1-5 patterns
- **🥈 Silver**: 6-15 patterns
- **🥇 Gold**: 16+ patterns
- **💎 Platinum**: Major contributions

### Hall of Fame
Top contributors will be:
- **Featured** in README.md
- **Invited** as collaborators
- **Recognized** in release notes

---

## 📞 Getting Help

### 💬 Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions
- **Discord**: Real-time chat (coming soon)
- **Email**: Direct communication

### 📚 Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Bug Bounty Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups)

---

## 🎯 Next Steps

### For New Contributors
1. **Start small** - fix existing patterns
2. **Learn the codebase** - understand patterns
3. **Join discussions** - engage with community
4. **Gradually contribute** - build expertise

### For Experienced Contributors
1. **Review PRs** - help maintain quality
2. **Mentor others** - guide new contributors
3. **Propose features** - suggest improvements
4. **Lead initiatives** - drive major changes

---

## 📄 License

By contributing to GF Patterns, you agree that your contributions will be licensed under the same [MIT License](LICENSE) as the project.

---

<div align="center">

**🚀 Ready to contribute? Start with a small pattern or bug fix!**

**💡 Every contribution makes the security community stronger!**

</div>
