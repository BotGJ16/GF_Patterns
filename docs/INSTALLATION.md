# 🚀 Installation Guide

Complete installation guide for **GF Patterns** - Elite security testing patterns.

---

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows with WSL2
- **Memory**: Minimum 4GB RAM, 8GB+ recommended
- **Storage**: 2GB free space for tools and patterns
- **Network**: Stable internet connection for tool downloads

### Required Tools
- **Git**: Version control
- **Go**: 1.19+ (for Go-based tools)
- **Python**: 3.8+ (for Python-based tools)
- **Bash**: Shell environment

---

## 🛠️ Installation Methods

### Method 1: Automated Installation (Recommended)

#### Quick Install Script
```bash
# Download and run the installer
curl -sSL https://raw.githubusercontent.com/your-repo/Gf-Patterns/main/install.sh | bash

# Or using wget
wget -qO- https://raw.githubusercontent.com/your-repo/Gf-Patterns/main/install.sh | bash
```

#### What the script does:
- ✅ Checks system requirements
- ✅ Installs required tools
- ✅ Downloads GF patterns
- ✅ Sets up environment variables
- ✅ Verifies installation

---

### Method 2: Manual Installation

#### Step 1: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    golang-go \
    build-essential
```

**CentOS/RHEL:**
```bash
sudo yum update -y
sudo yum install -y \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    golang \
    gcc
```

**macOS:**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install git wget curl python go
```

**Windows (WSL2):**
```bash
# In WSL2 terminal
sudo apt-get update
sudo apt-get install -y git wget curl python3 python3-pip golang-go
```

#### Step 2: Install Security Tools

##### Install Go-based tools:
```bash
# Create Go workspace
mkdir -p ~/go/{bin,src,pkg}
export GOPATH=~/go
export PATH=$PATH:$GOPATH/bin

# Install tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/OJ/gobuster/v3@latest
```

##### Install Python-based tools:
```bash
# Install pip packages
pip3 install --user \
    sqlmap \
    dirsearch \
    wapiti3 \
    w3af

# Install additional tools
pip3 install --user \
    requests \
    beautifulsoup4 \
    lxml \
    selenium
```

##### Install additional tools:
```bash
# Nmap
sudo apt-get install nmap

# Masscan (for large-scale port scanning)
sudo apt-get install masscan

# Nikto (web vulnerability scanner)
sudo apt-get install nikto

# WhatWeb (web technology detector)
sudo apt-get install whatweb
```

#### Step 3: Install GF Patterns

##### Clone the repository:
```bash
# Clone to home directory
cd ~
git clone https://github.com/your-repo/Gf-Patterns.git
cd Gf-Patterns
```

##### Install patterns:
```bash
# Make install script executable
chmod +x install.sh

# Run installation
./install.sh
```

---

### Method 3: Docker Installation

#### Using Docker (Containerized)
```bash
# Pull the Docker image
docker pull your-registry/gf-patterns:latest

# Run container
docker run -it --rm \
    -v $(pwd)/results:/app/results \
    -v $(pwd)/targets:/app/targets \
    your-registry/gf-patterns:latest
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  gf-patterns:
    image: your-registry/gf-patterns:latest
    volumes:
      - ./results:/app/results
      - ./targets:/app/targets
      - ./config:/app/config
    environment:
      - TARGET_FILE=/app/targets/targets.txt
      - OUTPUT_DIR=/app/results
```

---

## 🔧 Configuration

### Environment Setup

#### Add to shell profile:
```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'export GF_PATTERNS_HOME=~/Gf-Patterns' >> ~/.bashrc
echo 'export PATH=$PATH:$GF_PATTERNS_HOME/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Configure tools:
```bash
# Configure subfinder
subfinder -h

# Configure nuclei
nuclei -ut

# Configure sqlmap
sqlmap --update
```

### Pattern Configuration

#### Custom patterns:
```bash
# Create custom patterns directory
mkdir -p ~/.gf-patterns/custom

# Add custom patterns
cp your_custom_pattern.json ~/.gf-patterns/custom/
```

#### Update patterns:
```bash
# Update to latest patterns
cd ~/Gf-Patterns
git pull origin main
./update-patterns.sh
```

---

## ✅ Verification

### Test Installation
```bash
# Run verification script
./verify-installation.sh

# Expected output:
# ✅ Subfinder: OK
# ✅ Httpx: OK
# ✅ Nuclei: OK
# ✅ Gau: OK
# ✅ Dnsx: OK
# ✅ Gobuster: OK
# ✅ GF Patterns: OK
```

### Test Patterns
```bash
# Test XSS pattern
echo "https://example.com/search?q=test" | gf xss

# Test SQLi pattern
echo "https://example.com/page?id=1" | gf sqli

# Test SSRF pattern
echo "https://example.com/api?url=http://example.com" | gf ssrf
```

---

## 🐛 Troubleshooting

### Common Issues

#### Issue: Command not found
```bash
# Solution: Add to PATH
export PATH=$PATH:$HOME/go/bin
export PATH=$PATH:$HOME/.local/bin
```

#### Issue: Permission denied
```bash
# Solution: Fix permissions
chmod +x ~/Gf-Patterns/bin/*
sudo chown -R $USER:$USER ~/Gf-Patterns
```

#### Issue: Go tools not found
```bash
# Solution: Set Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
```

#### Issue: Python tools not found
```bash
# Solution: Add Python user bin to PATH
export PATH=$PATH:$HOME/.local/bin
echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
```

### Performance Issues

#### Memory optimization:
```bash
# Reduce memory usage
export GOGC=20
export GOMAXPROCS=2
```

#### Network optimization:
```bash
# Set DNS servers
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf
```

---

## 🔄 Updates

### Update All Tools
```bash
# Update Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/OJ/gobuster/v3@latest

# Update Python tools
pip3 install --user --upgrade sqlmap dirsearch wapiti3 w3af

# Update GF Patterns
cd ~/Gf-Patterns
git pull origin main
```

### Update Specific Tool
```bash
# Update single tool
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

---

## 🗑️ Uninstallation

### Complete Removal
```bash
# Remove tools
rm -rf ~/go/bin/{subfinder,httpx,nuclei,gau,dnsx,gobuster}
pip3 uninstall sqlmap dirsearch wapiti3 w3af

# Remove GF Patterns
rm -rf ~/Gf-Patterns
rm -rf ~/.gf-patterns

# Remove from PATH
sed -i '/GF_PATTERNS_HOME/d' ~/.bashrc
sed -i '/gf-patterns\/bin/d' ~/.bashrc
source ~/.bashrc
```

### Docker Cleanup
```bash
# Remove Docker containers
docker rm -f $(docker ps -aq)

# Remove Docker images
docker rmi your-registry/gf-patterns:latest

# Remove volumes
docker volume prune -f
```

---

## 📞 Support

### Getting Help
- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/BotGJ16)
- **Discussions**: [GitHub Discussions]()
- **Wiki**: [GitHub Wiki]()

### Community
- **Discord**: [Join our Discord]()
- **Twitter**: [@GFPatterns](https://x.com/Mahmadisha_786)
- **LinkedIn**: [GF Patterns](https://www.linkedin.com/in/mohammadisha-shaikh-2297a5240/)

---

<div align="center">

**🚀 Ready to start testing? Check out our [Security Testing Guide](SECURITY_TESTING.md)**

**📚 Need patterns? See our [Pattern Documentation](PATTERNS.md)**

**🤝 Want to contribute? Read our [Contributing Guide](CONTRIBUTING.md)**

</div>
