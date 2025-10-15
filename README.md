<!-- README for SubEnum God Mode - ULTIMATE PRO (English) --><div align="center">⚡️ SUBENUM GOD MODE — ULTIMATE PRO ⚡️

    

<p align="center">
  <img src="https://media.giphy.com/media/3o7aD2saalBwwftBIY/giphy.gif" alt="scan-demo" width="700" />
</p>🧠 2000+ lines of advanced recon power — No API keys required — Built for hunters, researchers, and professionals.

</div>
---

📘 Overview

SubEnum God Mode — ULTIMATE PRO is an all-in-one subdomain enumeration framework that combines:

🔍 Advanced DNS bruteforce and hybrid dictionary engines

🌐 Certificate Transparency (CT) analysis, ASN & resolver intelligence

🕸️ Deep JavaScript-enabled crawling and asset extraction

⚙️ Port/service discovery and takeover detection

🤖 ML-based risk analysis and clustering


Designed for penetration testers, bug bounty hunters, and red teams who need high accuracy and scale.


---

💎 Highlights

Feature	Description

Async DNS Engine	Multi-resolver, high-throughput async resolution with caching and retries
CT & ASN Scan	Pulls certificates and historical SANs from crt.sh and other CT sources, ASN intelligence included
Deep JS Crawler	Headless crawling with JS execution, discovers hidden endpoints and API leaks
Takeover Detection	Automated detection for 25+ cloud providers and dangling CNAMEs
PortScan Integration	Optional Nmap integration for 100+ common ports and service fingerprinting
ML Anomaly Detection	DBSCAN clustering, entropy-based anomaly detection, and predictive risk scoring
Interactive Reports	JSON, XLSX, and HTML reports with visualizations and filters



---

⚙️ Configuration

Main configuration file: config.yaml

Add custom wordlists to data/wordlist.txt

Tune max_threads, timeout, and async_limit according to your environment

Use --no-ml flag to disable ML modules on low-memory systems



---

🧠 Machine Learning Module

Analysis	Purpose

Entropy Analysis	Detect unusually formatted subdomains and potential wildcard patterns
DBSCAN Clustering	Group subdomains by similar network/feature profiles to find infrastructure clusters
Predictive Risk	Estimate risk score (0.0–1.0) per subdomain based on exposures and history


Feature extraction example:

def extract_features(name):
    return [
        len(name),
        name.count('.'),
        name.count('-'),
        sum(c.isdigit() for c in name),
        sum(c.isalpha() for c in name),
    ]


---

📊 Output Example

output/example.com_YYYYMMDD_HHMMSS/
├── reports/
│   ├── ultimate_report.json
│   ├── interactive_report.html
│   └── export.xlsx
├── screenshots/
├── logs/
└── db/scan_results.db

Report JSON snippet:

{
  "domain": "example.com",
  "found_subdomains": 153,
  "critical_risk": ["admin.example.com", "api.internal.example.com"],
  "avg_risk_score": 0.78
}


---

🧩 Tags & Topics

#SubdomainEnumeration #BugBounty #Recon #CyberSecurity
#InformationGathering #MachineLearning #Automation #OpenSource
#PythonTools #SecurityResearch #DNS #PortScanning
#TakeoverDetection #DeepCrawl #AIRecon


---

🔮 Visual Assets Included

🎞️ Demo GIF placeholder: /assets/demo-scan.gif (replace with your recorded demo)

🖼️ SVG logo placeholder: /assets/logo.svg

🏷️ HTML banner: /docs/banner.html

📘 One-page cheat-sheet: /README_SHORT.md (optional)

📗 How-to guide: /docs/HOWTO.md



---

📜 License

MIT License © 2024–2025 SubEnum God Mode Contributors


---

⚠️ Responsible Use & Disclaimer

This tool is powerful and can be misused. Only use it on systems you own or where you have explicit permission to test. Follow local laws and program rules (e.g., bug bounty scope). We are not responsible for illegal use.

Do NOT use this tool to:

Attack systems without authorization

Perform DDoS, exploit vulnerabilities, or conduct illegal activities



---

💬 Support & Contact

📧 Email: fangyuan1798p@gmail.com
🐙 GitHub: Issues & Discussions
💬 Telegram (optional): t.me/subenumgodmode


---

<div align="center">🌟 If you like this project, please ⭐ the repository on GitHub!

Built with ❤️ by the SubEnum God Mode Team

</div>
