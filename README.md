# advanced-api-security-tool
An advanced Python tool for detecting Insecure Direct Object Reference (IDOR) vulnerabilities in REST and GraphQL APIs through comprehensive testing and analysis.

Key Features
Automated discovery of API endpoints

IDOR vulnerability testing with intelligent test cases

Support for both REST and GraphQL APIs

Sensitive data detection in responses

Rate limiting to avoid detection

Multi-threaded scanning

JSON output format

A powerful Python tool for detecting Insecure Direct Object Reference (IDOR) vulnerabilities in web APIs.

## Features

- **API Discovery**: Automatically finds API endpoints from base URLs
- **Comprehensive Testing**: Tests for IDOR vulnerabilities with intelligent test cases
- **Multi-Protocol Support**: Works with both REST and GraphQL APIs
- **Sensitive Data Detection**: Identifies potentially sensitive information in responses
- **Rate Limiting**: Built-in delays to avoid detection and blocking
- **Parallel Scanning**: Multi-threaded for efficient scanning
- **Detailed Reporting**: JSON output with full vulnerability details

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/api-idor-scanner.git
cd api-idor-scanner
```
Install dependencies:

```bash
pip install -r requirements.txt
```
Usage
Basic scan:

```bash
python api_idor_scanner.py -f targets.txt -o results.json
Advanced options:
```
python api_idor_scanner.py \
  -f targets.txt \
  -o custom_results.json \
  -t 15 \
  -a "Bearer your_token_here" \
  --debug
Arguments
Argument	Description
-f, --file	File containing target URLs or domains (required)
-o, --output	Output JSON file (default: api_idor_results.json)
-t, --threads	Number of concurrent threads (default: 10)
-a, --auth	Authorization token for authenticated scans
--debug	Enable debug output

Output Format
Results are saved in JSON format with:

-Scan metadata
-Discovered API endpoints
-Found vulnerabilities (including test cases and sensitive data)
-Response details

Example Targets File
```
example.com
api.example.com/v2
https://test.site/graphql
```
Requirements
-Python 3.6+
-requests library
-beautifulsoup4 (for HTML parsing)
-argparse (included in standard library)
