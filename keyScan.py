import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import concurrent.futures
import json
import logging
from datetime import datetime

class JSSecurityScanner:
    def __init__(self):
        self.console = Console()
        self.setup_logging()
        
        # Patterns for detecting sensitive information
        self.patterns = {
            'API_KEY': [
    # Specific service API keys with strict formats
    r'sk_live_[0-9a-zA-Z]{24,32}',  # Stripe Secret Key
    r'pk_live_[0-9a-zA-Z]{24,32}',  # Stripe Public Key
    r'rk_live_[0-9a-zA-Z]{24,32}',  # Stripe Restricted Key
    r'sq0atp-[0-9A-Za-z\-_]{22}',   # Square Access Token
    r'sq0csp-[0-9A-Za-z\-_]{43}',   # Square Application Secret
    
    # API keys with identifiers - fixed to capture the whole match
    r'(?i)(?:api[_-]?key|api[_-]?token)["\s]*[:=]\s*["\'][a-zA-Z0-9_\-]{20,64}["\']',
    r'(?i)(?:auth[_-]?token|access[_-]?token)["\s]*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,64}["\']',
    r'(?i)bearer["\s]*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,64}["\']',
    
    # Payment service tokens
    r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',  # PayPal Access Token
    
    # Common API key formats with prefixes
    r'(?i)(?:pk|sk|api|key)_[live|test|prod]_[0-9a-zA-Z]{24,32}',
    r'(?i)api_key_[0-9a-zA-Z]{24,32}',
    
    # GitHub tokens
    r'gh[ps]_[0-9a-zA-Z]{36}',  # GitHub Personal Access Token
    r'github_pat_[0-9a-zA-Z]{82}',  # GitHub Fine-grained PAT
    
    # Firebase config keys
    r'AIza[0-9A-Za-z\-_]{35}',  # Firebase API Key
    
    # SendGrid API Keys
    r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    
    # Mailgun API Keys
    r'key-[0-9a-zA-Z]{32}',
    
    # OpenAI API Keys
    r'sk-[0-9a-zA-Z]{48}',
    
    # JWT Tokens
    r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
],
            'AWS_KEY': [
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'(?i)(aws[_-]?key|aws[_-]?secret)',
                r'(?i)(amazon[_-]?key|amazon[_-]?secret)'
            ],
            'GOOGLE_API': [
                r'AIza[0-9A-Za-z\-_]{35}',  # Google API Key
                r'(?i)(google[_-]?api[_-]?key|google[_-]?secret)'
            ],
            'CRYPTO_KEY': [
                r'(?i)(crypto[_-]?key|private[_-]?key)',
                r'(?i)(secret[_-]?key|encryption[_-]?key)'
            ],
            'DATABASE': [
                r'(?i)(mongodb(\+srv)?:\/\/[^\s]+)',  # MongoDB URI
                r'(?i)(postgresql:\/\/[^\s]+)',  # PostgreSQL URI
                r'(?i)(mysql:\/\/[^\s]+)',  # MySQL URI
                r'(?i)(database[_-]?url|db[_-]?connection)',
                       r'(?i)([\'"]?database[_-]?url[\'"]?\s*[:=]\s*[\'"][^\s<>"\']+[\'"])',
                r'(?i)([\'"]?db[_-]?password[\'"]?\s*[:=]\s*[\'"][^\s<>"\']+[\'"])',
                r'(?i)([\'"]?db[_-]?user[\'"]?\s*[:=]\s*[\'"][^\s<>"\']+[\'"])'
            ],
            'PASSWORD': [
                 r'(?i)([\'"]?password[\'"]?\s*[:=]\s*[\'"][^\s<>"\']{8,}[\'"])',
                r'(?i)([\'"]?passwd[\'"]?\s*[:=]\s*[\'"][^\s<>"\']{8,}[\'"])',
                r'(?i)([\'"]?pwd[\'"]?\s*[:=]\s*[\'"][^\s<>"\']{8,}[\'"])',
                r'(?i)([\'"]?secret[\'"]?\s*[:=]\s*[\'"][^\s<>"\']{8,}[\'"])'
            ],
           'EMAIL': [
    # Basic email pattern
    r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
    
   
    # Email in HTML context
    r'mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})',
    
    # Emails in assignments
    r'(?i)(?:email|mail|contact)[\s]*[=:]\s*[\'"]([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})[\'"]',
    
    # Emails in HTML attributes
    r'(?i)(?:email|mail|contact)[^>]+?>[\'"]?([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})[\'"]?</'
],
            'PRIVATE_KEY': [
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'-----BEGIN DSA PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----'
            ],
            'OAUTH': [
                r'(?i)(oauth[_-]?token|oauth[_-]?secret)',
                r'(?i)(client[_-]?id|client[_-]?secret)'
            ]
        }

    def is_false_positive(self, match: str, context: str) -> bool:
        """Enhanced check for false positives"""
        # Check for sequential or patterned strings
        def is_sequential_or_patterned(s):
            # Check for alphabetical sequence
            alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            if any(s.upper().find(alpha[i:i+5]) != -1 for i in range(len(alpha)-4)):
                return True
            
            # Check for numeric sequence
            nums = '0123456789'
            if any(s.find(nums[i:i+5]) != -1 for i in range(len(nums)-4)):
                return True
            
            # Check for repeated patterns
            if len(s) >= 8:
                # Check for repeating patterns of length 2-4
                for pattern_length in range(2, 5):
                    pattern = s[:pattern_length]
                    if pattern * (len(s) // pattern_length) in s:
                        return True
            
            # Check for keyboard patterns
            keyboard_rows = [
                'QWERTYUIOP',
                'ASDFGHJKL',
                'ZXCVBNM'
            ]
            s_upper = s.upper()
            for row in keyboard_rows:
                if any(s_upper.find(row[i:i+4]) != -1 for i in range(len(row)-3)):
                    return True
            
            return False

        # Check for obvious test strings
        false_positive_patterns = [
            # Sequential and patterned strings
            r'(?i)abcdef',
            r'(?i)ABCDEF',
            r'(?i)123456',
            r'(?i)qwerty',
            r'(?i)test123',
            
            # Common placeholder patterns
            r'(?i)example[a-z0-9]+',
            r'(?i)sample[a-z0-9]+',
            r'(?i)test[a-z0-9]+',
            r'(?i)demo[a-z0-9]+',
            r'(?i)dummy[a-z0-9]+',
            
            # Development/placeholder strings
            r'(?i)development[a-z0-9]+',
            r'(?i)staging[a-z0-9]+',
            r'(?i)production[a-z0-9]+',
            r'(?i)placeholder[a-z0-9]+',
            
            # Common code patterns
            r'function\s+\w*token\w*\s*\(',
            r'(var|let|const)\s+\w*token',
            r'typeof\s+\w*token',
            r'\w*token\s*:\s*{',
            r'\w*token\s*\?',
            r'\btoken\b\s*\.',
            
            # HTML/CSS related
            r'<.*token.*>',
            r'class=["\'].*token.*["\']',
            r'id=["\'].*token.*["\']',
            
            # Common validation/example patterns
            r'(?i)valid[a-z0-9]+',
            r'(?i)invalid[a-z0-9]+',
            r'(?i)example[a-z0-9]+',
            r'(?i)template[a-z0-9]+',
            
            # Comments
            r'\/\/.*key',
            r'\/\*.*key.*\*\/',
            
            # Common false positive strings
            r'0{8,}',          # Repeated zeros
            r'1{8,}',          # Repeated ones
            r'a{8,}',          # Repeated letters
            r'x{8,}',          # Repeated x's
            
            # Documentation patterns
            r'(?i)your[_-]?api[_-]?key[_-]?here',
            r'(?i)insert[_-]?api[_-]?key[_-]?here',
            r'(?i)replace[_-]?with[_-]?your',
            r'(?i)enter[_-]?your[_-]?key',
        ]

        # Check against false positive patterns
        if any(re.search(pattern, context, re.I) for pattern in false_positive_patterns):
            return True

        # Check if the match itself is sequential or patterned
        if is_sequential_or_patterned(match):
            return True

        # Check for repeated characters
        if re.search(r'(.)\1{7,}', match):
            return True

        # Check for alternating patterns
        if re.search(r'(..)(?:\1){3,}', match):
            return True

        # Check if it's in a validation/test context
        validation_contexts = [
            r'test',
            r'valid',
            r'invalid',
            r'example',
            r'sample',
            r'template',
            r'placeholder',
            r'documentation',
            r'tutorial'
        ]
        
        if any(re.search(f'(?i){pattern}', context) for pattern in validation_contexts):
            return True

        return False

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            filename=f'js_security_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def get_js_files(self, url: str) -> list:
        """Extract all JavaScript file URLs from a webpage"""
        js_files = []
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(url, headers=headers, timeout=15, verify=True)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = response.url
            
            # Find inline scripts
            inline_scripts = soup.find_all('script', string=True)
            for script in inline_scripts:
                if script.string and not script.get('src'):
                    js_files.append(('inline', script.string.strip()))
            
            # Find external scripts
            external_scripts = soup.find_all('script', src=True)
            for script in external_scripts:
                src = script.get('src', '').strip()
                if src:
                    full_url = self.normalize_url(src, base_url)
                    if full_url:
                        js_files.append(('external', full_url))
            
            # Find event handlers
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.lower().startswith('on') and isinstance(tag[attr], str):
                        js_files.append(('event', tag[attr].strip()))
            
            return js_files
            
        except Exception as e:
            logging.error(f"Error fetching JavaScript files: {str(e)}")
            return js_files


    def scan_content(self, content: str) -> dict:
        """Scan content for sensitive information"""
        findings = {}
        
        for category, patterns in self.patterns.items():
            matches = []
            for pattern in patterns:
                found = re.finditer(pattern, content)
                for match in found:
                    matched_text = match.group()
                    context = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
                   
                        
                    matches.append({
                        'match': matched_text,
                        'context': context.strip(),
                        'pattern': pattern
                    })
                    
                  
                        
            if matches:
                findings[category] = matches
        
        return findings

    def fetch_js_content(self, js_url: str) -> str:
        """Fetch content of external JavaScript file with improved error handling"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'script',
                'Sec-Fetch-Mode': 'no-cors',
                'Sec-Fetch-Site': 'same-origin',
                'Pragma': 'no-cache',
                'Cache-Control': 'no-cache'
            }

            session = requests.Session()
            
            # First try with SSL verification
            try:
                response = session.get(
                    js_url,
                    headers=headers,
                    timeout=15,
                    verify=True,
                    allow_redirects=True
                )
                response.raise_for_status()
            except requests.exceptions.SSLError:
                # Retry without SSL verification if SSL fails
                response = session.get(
                    js_url,
                    headers=headers,
                    timeout=15,
                    verify=False,
                    allow_redirects=True
                )
                response.raise_for_status()

            # Check content type
            content_type = response.headers.get('content-type', '').lower()
            if not any(js_type in content_type for js_type in ['javascript', 'application/x-javascript', 'text/plain']):
                if not js_url.endswith('.js'):
                    logging.warning(f"Non-JavaScript content type for {js_url}: {content_type}")
                    return ""

            return response.text

        except Exception as e:
            logging.error(f"Error fetching JavaScript from {js_url}: {str(e)}")
            return ""
        
    def normalize_url(self, url: str, base_url: str) -> str:
        """Normalize and validate JavaScript URLs"""
        try:
            # Handle protocol-relative URLs
            if url.startswith('//'):
                url = 'https:' + url
            # Handle absolute URLs
            elif url.startswith(('http://', 'https://')):
                pass
            # Handle root-relative URLs
            elif url.startswith('/'):
                url = urljoin(base_url, url)
            # Handle relative URLs
            else:
                url = urljoin(base_url, url)
            
            return url
        except Exception as e:
            self.console.print(f"[red]Error normalizing URL {url}: {str(e)}[/red]")
            return None

    def scan_url(self, url: str) -> dict:
        """Main scanning function"""
        results = {
            'url': url,
            'scan_time': datetime.now().isoformat(),
            'findings': {},
            'errors': [],
            'stats': {
                'js_files_found': 0,
                'files_scanned': 0,
                'findings_count': 0
            }
        }
        
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            with Progress(transient=True) as progress:
                # Step 1: Get JS files
                fetch_task = progress.add_task("[cyan]Finding JavaScript files...", total=1)
                js_files = self.get_js_files(url)
                progress.update(fetch_task, completed=1)
                
                if not js_files:
                    self.console.print("[red]No JavaScript files found![/red]")
                    results['errors'].append("No JavaScript files found")
                    return results
                
                results['stats']['js_files_found'] = len(js_files)
                
                # Step 2: Scan each file
                scan_task = progress.add_task(
                    f"[green]Scanning {len(js_files)} JavaScript files...",
                    total=len(js_files)
                )
                
                for js_type, js_content in js_files:
                    try:
                        if js_type == 'external':
                            content = self.fetch_js_content(js_content)
                            if content:
                                findings = self.scan_content(content)
                                if findings:
                                    results['findings'][js_content] = findings
                                    results['stats']['findings_count'] += sum(len(matches) for matches in findings.values())
                        else:
                            findings = self.scan_content(js_content)
                            if findings:
                                results['findings'][f"{js_type}_script"] = findings
                                results['stats']['findings_count'] += sum(len(matches) for matches in findings.values())
                        
                        results['stats']['files_scanned'] += 1
                        
                    except Exception as e:
                        results['errors'].append(f"Error scanning {js_type} source: {str(e)}")
                    
                    progress.update(scan_task, advance=1)
            
            # Final summary
            if results['stats']['findings_count'] > 0:
                self.console.print(f"\n[yellow]Found {results['stats']['findings_count']} potential security issues[/yellow]")
            else:
                self.console.print("\n[green]No security issues found[/green]")
            
        except Exception as e:
            results['errors'].append(f"Error during scan: {str(e)}")
        
        return results

    def generate_report(self, results: dict):
        """Generate a detailed report of findings"""
        # Console output
        self.console.print("\n[bold blue]JavaScript Security Scan Report[/bold blue]")
        self.console.print(f"URL: {results['url']}")
        self.console.print(f"Scan Time: {results['scan_time']}")
        
        if not results['findings']:
            self.console.print("\n[green]No sensitive information found![/green]")
            return
        
        # Create findings table
        table = Table(show_header=True)
        table.add_column("Source")
        table.add_column("Category")
        table.add_column("Match")
        table.add_column("Context")
        
        for source, categories in results['findings'].items():
            for category, matches in categories.items():
                for match in matches:
                    table.add_row(
                        str(source),
                        category,
                        match['match'],
                        match['context']
                    )
        
        self.console.print(table)
        
        # Save to JSON
        filename = f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.console.print(f"\n[yellow]Detailed report saved to: {filename}[/yellow]")

def main():
    scanner = JSSecurityScanner()
    
    url = input("Enter the URL to scan: ")
    scanner.console.print(f"\n[bold]Starting scan of: {url}[/bold]")
    
    results = scanner.scan_url(url)
    scanner.generate_report(results)

if __name__ == "__main__":
    main()

