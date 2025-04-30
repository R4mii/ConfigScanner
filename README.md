# ConfigScanner

A powerful configuration file and credential scanner for web applications security assessment.


## Overview

ConfigScanner is an advanced web application security tool designed to identify exposed configuration files, environment variables, and credentials across multiple domains. It automatically tests discovered credentials to verify their validity, making it valuable for security assessments and penetration testing.

## Features

- **Multithreaded scanning**: Scan multiple domains simultaneously
- **Comprehensive path coverage**: Checks for 40+ common configuration files and endpoints
- **Credential detection**: Identifies multiple credential types including:
  - AWS access keys
  - Database credentials
  - API tokens
  - SMTP credentials
  - Twilio keys
  - Stripe keys
  - GitHub tokens
  - Firebase credentials
  - JWT secrets
  - SSH keys
  - And more...
- **Credential validation**: Actively tests discovered credentials to verify their validity
- **Debug mode detection**: Identifies applications with debugging enabled
- **Detailed reporting**: Generates both summary and detailed reports
- **Colorized output**: User-friendly terminal interface with progress tracking

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/configscanner.git
cd configscanner

# Install dependencies
pip install -r 
```

### Dependencies

- requests
- concurrent.futures
- colorama
- tqdm
- boto3
- twilio
- smtplib

## Usage

### Basic Usage

```bash
python ConfigScanner.py -l domains.txt
```

### Command Line Arguments

```
usage: ConfigScanner.py [-h] [-l LIST] [-t THREADS] [-o OUTPUT] [-T TIMEOUT] [-v] [-s SINGLE] [-n]

Advanced Configuration Scanner with Credential Testing

options:
  -h, --help            show this help message and exit
  -l LIST, --list LIST  File containing list of domains to scan
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  -o OUTPUT, --output OUTPUT
                        Output directory for results
  -T TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 15)
  -v, --verbose         Enable verbose output
  -s SINGLE, --single SINGLE
                        Scan a single domain
  -n, --no-test         Disable credential testing
```

### Examples

Scan a single domain:
```bash
python ConfigScanner.py -s example.com
```

Scan multiple domains from a file with 20 threads:
```bash
python ConfigScanner.py -l domains.txt -t 20
```

Scan with verbose output and custom timeout:
```bash
python ConfigScanner.py -l domains.txt -v -T 30
```

Scan without credential testing:
```bash
python ConfigScanner.py -l domains.txt -n
```

Custom output directory:
```bash
python ConfigScanner.py -l domains.txt -o /path/to/output
```

## Output

The scanner creates a timestamped directory to store all result files:

```
output/YYYY-MM-DD_HH-MM-SS/
├── scanned_domains.txt           # List of all domains scanned
├── summary.json                  # Summary of scan results
├── aws_credentials.txt           # URLs with AWS credentials
├── database_credentials.txt      # URLs with database credentials
├── detailed_aws_credentials.txt  # Detailed AWS credential findings
├── valid_credentials.txt         # Successfully validated credentials
└── ...                           # Other credential type files
```

## Caution

This tool is intended for legitimate security testing with proper authorization. Unauthorized scanning of systems may violate laws and regulations. Always ensure you have permission before scanning any system.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Developed by: v01_dy
- Enhanced version with credential testing