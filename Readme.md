# 🛡️ WebScan - Website Vulnerability Scanner & Technology Detector

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.7+-blue?logo=python)

## 📌 Overview

**WebScan** is a Python-based CLI tool designed for ethical hacking and security auditing purposes. It helps you detect:

- ⚙️ Technologies used by a website  
- 🚨 Common security vulnerabilities  
- 📡 Open network ports  
- 🔒 SSL/TLS certificate information  
- 📜 HTTP header security issues  

---

## ✍️ Author

**Anshtech Solutions**  
🌐 Website: [www.anshtechsolutions.tech](https://www.anshtechsolutions.tech)

---

## 🧰 Features

- 🕵️ Detects outdated & vulnerable technologies  
- 🔐 Analyzes SSL certificates and reports weak configurations  
- 🧪 Checks for missing HTTP security headers  
- 🔍 Scans for dangerous open ports using `nmap`  
- 🧠 Provides smart suggestions for remediation  

---

## 🚀 Quick Start

```bash
git clone https://github.com/Anshulrazz/webscan.git
cd webscan
pip install -r requirements.txt
python3 webscan.py --url https://example.com --output results.json --scan-level full
```

---

## ⚙️ Dependencies

Make sure you have the following installed:

```bash
pip install builtwith requests beautifulsoup4 colorama python-nmap pyOpenSSL tqdm
```

Also, ensure **Nmap** is installed and added to your system’s PATH.

---

## 🛠️ Options

| Option        | Description                        |
|---------------|------------------------------------|
| `--url`       | Target website URL                 |
| `--output`    | (Optional) Output file (JSON)      |
| `--scan-level`| Scan intensity: `quick` or `full`  |

---

## 🖥️ Sample Output

```json
{
  "target": "https://example.com",
  "scan_time": "2025-04-20 12:00:00",
  "technologies": [{"name": "Apache", "category": "Web Server"}],
  "vulnerabilities": [{"name": "Missing CSP", "severity": "Medium"}],
  "open_ports": [{"port": 443, "service": "https"}],
  "ssl_info": {"issuer": "Let's Encrypt", "days_remaining": 45},
  "headers": {"X-Frame-Options": "DENY"}
}
```

---

## 🧑‍💻 Contributing

Contributions are welcome!  
Please fork this repo and submit a pull request.

---

## 📄 License

This project is licensed under the MIT License.  
See the `LICENSE` file for more details.

---

> Built with ❤️ by [Anshtech Solutions](https://www.anshtechsolutions.tech)
```
