# Subenum
# 🧠 QuQuSubEnum — Advanced Recon & Intelligence Framework

**QuQuSubEnum** is an advanced, modular reconnaissance and intelligence framework for ethical hackers, security researchers, and data analysts.  
Built to combine OSINT, automation, and data science for powerful but responsible reconnaissance workflows.

**Author:** Moh Agus © 2025  
**License:** MIT (see `LICENSE`)

---

## 🚀 Project Summary

QuQuSubEnum provides:
- Modular recon pipeline (passive → active → analysis)
- Async scanning engine (throttling & rate limiting)
- AI-assisted analysis (clustering, anomaly detection)
- Visualizers: `networkx`, charts, wordclouds
- Extensible architecture — integrate custom modules, outputs, and report formats

This tool is designed for **ethical** research, training, and defensive security. It is **NOT** intended for illegal or unauthorized activity.

---

## ✨ Features (Detailed)

- **Passive Recon**
  - WHOIS, DNS records, SSL/TLS info, tldextract
  - HTTP fingerprinting, robots.txt parsing, sitemap discovery
- **Active Recon (opt-in)**
  - Port probes (throttled), HTTP crawls, form discovery
  - Optional integration with `shodan` & `censys` (user-provided API keys)
- **OSINT Enrichment**
  - Subdomain enumeration, reverse DNS, certificate transparency logs
- **Data Science & AI**
  - Data clustering, anomaly detection (scikit-learn)
  - Graph analysis with `networkx` and visual outputs
- **Automation & Safety**
  - Async engine with `asyncio` + `aiohttp`
  - Built-in throttling, concurrency limits, and "safe mode"
- **Reporting**
  - Export JSON, CSV, and human-readable HTML reports
- **Extensibility**
  - Plugin hooks for input, transform, and output stages

---

## ⚙️ System Requirements

- OS: Debian/Ubuntu/Kali or similar Linux (x86_64 recommended)
- Python: 3.10+
- Disk: 500MB+ (depends on outputs)
- Network: Optional for external APIs/browsing

### Native dependencies (Debian/Ubuntu/Kali example)
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv build-essential \
 libssl-dev libffi-dev zlib1g-dev libjpeg-dev libpng-dev libfreetype-dev \
 libxml2-dev libxslt1-dev libopenblas-dev liblapack-dev gfortran rustc \
 libpcap-dev chromium chromedriver firefox-geckodriver
