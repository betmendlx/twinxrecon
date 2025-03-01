# TwinXRecon v1

**TwinXRecon** is a comprehensive reconnaissance tool that automates and streamlines the process of gathering information about a target domain, including subdomain enumeration, URL collection, sensitive file detection, JavaScript analysis, and vulnerability scanning.

![TwinXRecon](https://img.shields.io/badge/Tool-TwinXRecon-blue)
![Version](https://img.shields.io/badge/Version-1.0-green)
![Python](https://img.shields.io/badge/Language-Python%203-yellow)
![License](https://img.shields.io/badge/License-MIT-red)

## Features

- 🔍 **Subdomain Enumeration**: Discovers subdomains using subfinder
- 🌐 **Live Subdomain Verification**: Identifies active subdomains with httpx
- 📚 **URL Collection**: Gathers historical URLs from Wayback Machine
- 📝 **URL Filtering**: Cleans and organizes URLs with uro
- 🔒 **Sensitive File Detection**: Identifies potentially sensitive files and configurations
- 📜 **JavaScript Analysis**: Extracts potential secrets from JavaScript files
- 🛡️ **Vulnerability Scanning**: Scans for security vulnerabilities using Nuclei
- 📊 **Summary Reporting**: Provides a comprehensive summary of findings

## Prerequisites

TwinXRecon requires the following tools to be installed and available in your PATH:

- subfinder
- httpx
- waybackurls
- uro
- secretfinder
- nuclei (with templates)

Additionally, Python 3 with the following packages:
- colorama
- tqdm
- argparse

## Installation

```bash
# Clone the repository
git clone https://github.com/betmendlx/twinxrecon.git
cd twinxrecon

# Install required Python packages
pip3 install -r requirements.txt

# Make the script executable
chmod +x twinxrecon.py
```

## Usage

```bash
python3 twinxrecon.py -d example.com -t /path/to/nuclei-templates/ -w 10
```

### Arguments

- `-d, --domain`: Target domain (required)
- `-t, --templates`: Path to Nuclei templates folder (default: /home/user/nuclei-templates/)
- `-w, --workers`: Number of worker threads for parallelism (default: 10)

## Workflow

1. **Subdomain Enumeration**: The tool first uses subfinder to discover all subdomains related to the target domain.
2. **Live Subdomain Verification**: It then employs httpx to verify which of the discovered subdomains are live.
3. **URL Collection**: The tool collects historical URLs from the Wayback Machine for comprehensive coverage.
4. **URL Filtering**: Collected URLs are filtered and optimized using uro.
5. **Sensitive File Detection**: It searches for potentially sensitive files in the collected URLs.
6. **JavaScript Analysis**: The tool analyzes JavaScript files for exposed secrets or credentials.
7. **Vulnerability Scanning**: Finally, it can scan the target for vulnerabilities using Nuclei.

## Output Files

TwinXRecon organizes its findings into various output files:

- Subdomain lists
- Live subdomain lists
- Collected URLs
- Sensitive file paths
- JavaScript file paths
- Extracted secrets
- Vulnerability reports (categorized by severity)

All results are also summarized in the terminal output.

## Example Output

```
=== Summary Execution for example.com ===
Subdomains Found: 152
Live Subdomains: 87
URLs Collected: 4328
Sensitive Files Found: 23
JS Files Found: 189
Secrets Found:
  - aws: 3
  - twilio: 0
  - google: 5
  - heroku: 1
Vulnerabilities (Nuclei):
  - low     : ##### (26)
  - medium  : ### (15)
  - high    : # (7)
  - critical: - (0)
============================
```

## Security Notes

- TwinXRecon sets restrictive file permissions (0o600) on output files to protect sensitive information
- All temporary files are cleaned up after execution
- A detailed log file is maintained for audit purposes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and ethical testing purposes only. Always ensure you have proper authorization before performing reconnaissance on any domain.

## Author

- betmen0x0
