# 🔑 KeyHunter - Burp Suite Passive Scanner Extension

KeyHunter is a powerful Burp Suite extension that passively scans HTTP responses for potential sensitive information exposures, such as API keys, access tokens, credentials, and secrets. It combines precise regex patterns and keyword-based detection with contextual validation to reduce false positives.

## 📦 Features

- 🧠 **Context-Aware Scanning** – Skips dummy/test/example data
- 🔍 **Regex-Based Detection** – JWTs, AWS Keys, IPs, Private Keys, DB connections, etc.
- 🧰 **Keyword-Based Detection** – Matches 300+ sensitive keywords like `api_key`, `password`, `auth_token`, etc.
- 🔒 **JWT Validation** – Confirms Base64 structure and decodes payload
- 📄 **MIME-Type Filtering** – Ignores non-text content like images or fonts
- ⚖️ **Confidence-Based Severity** – High confidence issues marked as High severity

---

## 🛠 Installation Instructions

### Requirements
- Burp Suite (Community or Pro)
- Jython standalone JAR (recommended: `jython-standalone-2.7.2.jar`)

### Step-by-Step Setup

1. Download the [KeyHunter.py](https://github.com/sudosuraj/KeyHunter) script or clone the repo:
   ```bash
   git clone https://github.com/sudosuraj/KeyHunter.git
   ```
2. Go to the Extensions tab → click Add
  Extension Type: Python
  Extension File: Select KeyHunter.py

## 🤝 Contributing
Found a bug or want to improve detection patterns? Pull requests are welcome!


