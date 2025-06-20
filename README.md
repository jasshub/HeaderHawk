# 🦅 HeaderHawk

HeaderHawk is a Python-based CLI tool designed to evaluate a web application's security posture by analyzing HTTP response headers. It highlights potential misconfigurations, scores header implementations, and delivers clear, color-coded guidance for remediation.

##  Features

- Checks key security headers (HSTS, CSP, X-Frame-Options, etc.)
- Scoring system: ✅ 10/10, ⚠️ 5/10, ❌ 0/10
- Recommendations with reasons
- Color-coded CLI output using `colorama`
##  Example Usage

```bash
python headerhawk.py
```

```
🌐 Enter the website URL (e.g., example.com or https://example.com): example.com
```

##  Requirements

- Python 3.6+
- Install dependencies:

```bash
pip install -r requirements.txt
```
