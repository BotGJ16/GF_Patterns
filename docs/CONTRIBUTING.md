# 🤝 Contributing Guide

Welcome to **GF Patterns**! This guide will help you contribute to our elite security testing patterns collection.

---

## 🎯 How to Contribute

### 🆕 Adding New Patterns

#### Step 1: Pattern Research
Before creating a new pattern:
1. **Research the vulnerability** thoroughly
2. **Test against real targets** (legally)
3. **Document edge cases** and false positives
4. **Create comprehensive examples**

#### Step 2: Pattern Structure
Create your pattern file in the appropriate directory:

```bash
# Web vulnerabilities
nano patterns/web/new_vulnerability.json

# Infrastructure
nano patterns/infrastructure/new_pattern.json

# Cloud security
nano patterns/cloud/new_pattern.json
```

#### Step 3: Pattern Format
```json
{
    "flags": "-HanrE",
    "pattern": "your_comprehensive_regex_pattern",
    "description": "Clear description of what this detects",
    "severity": "HIGH|MEDIUM|LOW",
    "category": "vulnerability_type",
    "references": [
        "https://owasp.org/link",
        "https://cwe.mitre.org/link"
    ],
    "examples": [
        "https://example.com/vulnerable?param=attack_vector",
        "https://example.com/another_example"
    ]
}
```

---

### 🧪 Pattern Testing

#### Test Suite Structure
```bash
tests/
├── web/
│   ├── xss_test_cases.txt
│   ├── sqli_test_cases.txt
│   └── new_vulnerability_test_cases.txt
├── infrastructure/
└── cloud/
```

#### Testing Commands
```bash
# Test your pattern
cat tests/web/new_vulnerability_test_cases.txt | gf new_vulnerability

# Validate false positives
cat tests/web/false_positives.txt | gf new_vulnerability

# Performance testing
time cat large_dataset.txt | gf new_vulnerability
```

---

### 📋 Pull Request Process

#### 1. Fork & Branch
```bash
# Fork the repository
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Gf-Patterns.git
cd Gf-Patterns

# Create feature branch
git checkout -b feature/new-vulnerability-pattern
```

#### 2. Pattern Development
```bash
# Create pattern file
nano patterns/web/new_vulnerability.json

# Add test cases
nano tests/web/new_vulnerability_test_cases.txt

# Update documentation
nano docs/PATTERNS.md
```

#### 3. Quality Checklist
- [ ] Pattern follows JSON structure
- [ ] Comprehensive regex testing
- [ ] False positive analysis
- [ ] Performance impact assessment
- [ ] Documentation updated
- [ ] Test cases provided

#### 4. Commit & Push
```bash
# Add changes
git add patterns/web/new_vulnerability.json
git add tests/web/new_vulnerability_test_cases.txt
git add docs/PATTERNS.md

# Commit with descriptive message
git commit -m "Add new vulnerability pattern for XYZ

- Detects ABC vulnerability
- Includes comprehensive test cases
- Updated documentation
- Performance tested on 1M+ URLs"

# Push to your fork
git push origin feature/new-vulnerability-pattern
```

#### 5. Create Pull Request
- **Title**: `Add [Vulnerability Type] Pattern`
- **Description**: Include:
  - Vulnerability explanation
  - Testing methodology
  - Real-world examples
  - Performance metrics

---

### 🏷️ Pattern Categories

#### Web Application Security
- **XSS** (Cross-Site Scripting)
- **SQLi** (SQL Injection)
- **SSRF** (Server-Side Request Forgery)
- **IDOR** (Insecure Direct Object Reference)
- **LFI/RFI** (Local/Remote File Inclusion)
- **SSTI** (Server-Side Template Injection)
- **XXE** (XML External Entity)
- **NoSQL Injection
- **GraphQL Injection
- **JWT Attacks

#### Infrastructure Security
- **Privilege Escalation
- **Lateral Movement
- **Persistence Mechanisms
- **Container Escape
- **Network Scanning
- **Service Enumeration

#### Cloud Security
- **AWS Misconfigurations
- **Azure Security Issues
- **GCP Vulnerabilities
- **Container Security
- **Kubernetes Security
- **API Security

#### Web3/Crypto Security
- **Smart Contract Vulnerabilities
- **Wallet Security
- **DeFi Exploits
- **Blockchain Analysis

---

### 🧪 Testing Standards

#### Test Case Requirements
```bash
# Positive test cases (should match)
cat > tests/web/xss_positive.txt << EOF
https://example.com/search?q=<script>alert(1)</script>
https://example.com/page?callback=javascript:alert(1)
https://example.com/data:text/html,<script>alert(1)</script>
EOF

# Negative test cases (should NOT match)
cat > tests/web/xss_negative.txt << EOF
https://example.com/search?q=normal+search
https://example.com/page?callback=valid_function
https://example.com/data:text/html,valid_content
EOF
```

#### Performance Benchmarks
```bash
# Test on large datasets
time cat 1million_urls.txt | gf xss

# Memory usage
/usr/bin/time -v cat 1million_urls.txt | gf xss

# False positive rate
python3 scripts/false_positive_analyzer.py xss
```

---

### 📊 Pattern Validation

#### Automated Testing
```bash
# Run test suite
./scripts/test_patterns.sh

# Validate JSON syntax
./scripts/validate_json.sh

# Performance benchmarks
./scripts/benchmark.sh
```

#### Manual Review Process
1. **Security Expert Review**
2. **Performance Analysis**
3. **False Positive Testing**
4. **Real-world Validation**
5. **Documentation Review**

---

### 🎨 Documentation Standards

#### Pattern Documentation
```markdown
## [Vulnerability Name]

### Description
Brief explanation of the vulnerability

### Pattern Details
- **File**: `patterns/category/vulnerability.json`
- **Severity**: HIGH/MEDIUM/LOW
- **Category**: vulnerability_type

### Examples
- Vulnerable: `https://example.com/vulnerable?param=attack`
- Safe: `https://example.com/safe?param=normal`

### Testing
```bash
cat test_cases.txt | gf vulnerability
```

### References
- [OWASP Link](https://owasp.org)
- [CWE Link](https://cwe.mitre.org)
```

---

### 🐛 Bug Reports

#### Bug Report Template
```markdown
**Pattern Name**: [Which pattern has the issue]
**Issue Type**: [False Positive/False Negative/Performance/Other]
**Description**: [Clear description of the issue]
**Test Case**: [URL or data that demonstrates the issue]
**Expected Behavior**: [What should happen]
**Actual Behavior**: [What actually happens]
**Environment**: [OS, gf version, etc.]
```

#### Submit Bug Report
1. **Check existing issues** first
2. **Create detailed reproduction steps**
3. **Include test data**
4. **Provide environment details**

---

### 💡 Feature Requests

#### Feature Request Template
```markdown
**Feature Type**: [New Pattern/Enhancement/Tool Integration]
**Description**: [Detailed description]
**Use Case**: [Why is this needed?]
**Implementation Ideas**: [How could this be implemented?]
**Priority**: [High/Medium/Low]
```

---

### 🏆 Recognition

#### Contributor Levels
- **🥉 Bronze**: 1-3 patterns
- **🥈 Silver**: 4-7 patterns
- **🥇 Gold**: 8+ patterns
- **💎 Diamond**: Exceptional contributions

#### Hall of Fame
Top contributors will be featured in:
- README.md contributors section
- Special recognition in releases
- Early access to new features

---

### 📞 Getting Help

#### Community Channels
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: General questions and ideas
- **Security**: security@gf-patterns.com

#### Resources
- [Pattern Development Guide](PATTERN_DEVELOPMENT.md)
- [Testing Documentation](TESTING.md)
- [Security Research Resources](SECURITY_RESOURCES.md)

---

### 🎯 Quick Start Checklist

For new contributors:
- [ ] Read this guide completely
- [ ] Set up development environment
- [ ] Test existing patterns
- [ ] Choose vulnerability to work on
- [ ] Create pattern following standards
- [ ] Write comprehensive tests
- [ ] Update documentation
- [ ] Submit pull request

---

<div align="center">

**🚀 Ready to contribute? Start with our [Good First Issues](https://github.com/your-repo/Gf-Patterns/labels/good-first-issue)!**

**💡 Have questions? Join our [Discussions](https://github.com/your-repo/Gf-Patterns/discussions)!**

**🛡️ Together, we make security testing more effective!**

</div>