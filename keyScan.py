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
                r'(?i)([a-z0-9]{32})',  # Generic API key pattern
                r'(?i)(api[_-]?key[_-]?=|\bapi[_-]?key\b)',
                r'(?i)(auth[_-]?token[_-]?=|\bauth[_-]?token\b)',
                r'(?i)(access[_-]?token[_-]?=|\baccess[_-]?token\b)',
                r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{32,}',
                r'sk_live_[0-9a-zA-Z]{24}',  # Stripe Secret Key
                r'pk_live_[0-9a-zA-Z]{24}',  # Stripe Public Key
                r'rk_live_[0-9a-zA-Z]{24}',  # Stripe Restricted Key
                r'sq0atp-[0-9A-Za-z\-_]{22}',  # Square Access Token
                r'sq0csp-[0-9A-Za-z\-_]{43}',  # Square Application Secret
                r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',  # PayPal Access Token
                r'sk_test_[0-9a-zA-Z]{24}'  # Stripe Test Key
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
                r'(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}',
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
        """Check if the match is likely a false positive"""
        false_positive_patterns = [
            r'function\s+\w*password\w*\s*\(',  # Function declarations
            r'(var|let|const)\s+password',      # Variable declarations
            r'typeof\s+password',               # Type checks
            r'password\s*:\s*{',                # Object properties
            r'password\s*\?',                   # Optional chaining
            r'\bpassword\b\s*\.',              # Property access
            r'validate[A-Za-z]*password',       # Validation functions
            r'check[A-Za-z]*password',          # Check functions
            r'\/\/.*password',                  # Comments
            r'\/\*.*password.*\*\/',            # Multi-line comments
            r'placeholder=[\'"]password[\'"]',   # HTML attributes
            r'name=[\'"]password[\'"]',         # Form fields
            r'id=[\'"]password[\'"]',           # Element IDs
        ]

        return any(re.search(pattern, context, re.I) for pattern in false_positive_patterns)

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            filename=f'js_security_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def get_js_files(self, url: str) -> list:
        """Extract all JavaScript file URLs from a webpage"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            js_files = []
            
            # Find inline scripts
            inline_scripts = soup.find_all('script', string=True)
            for script in inline_scripts:
                if script.string:
                    js_files.append(('inline', script.string))
            
            # Find external scripts
            external_scripts = soup.find_all('script', src=True)
            for script in external_scripts:
                src = script.get('src')
                if src:
                    full_url = urljoin(url, src)
                    js_files.append(('external', full_url))
            
            return js_files
        
        except Exception as e:
            logging.error(f"Error fetching JavaScript files from {url}: {str(e)}")
            return []

    def scan_content(self, content: str) -> dict:
        """Scan content for sensitive information"""
        findings = {}
        
        for category, patterns in self.patterns.items():
            matches = []
            for pattern in patterns:
                found = re.finditer(pattern, content)
                for match in found:
                    context = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
                    if self.is_false_positive(match.group(), context):
                        continue
                    matches.append({
                        'match': match.group(),
                        'context': context.strip(),
                        'pattern': pattern
                    })
            if matches:
                findings[category] = matches
        
        return findings

    def fetch_js_content(self, js_url: str) -> str:
        """Fetch content of external JavaScript file"""
        try:
            response = requests.get(js_url, timeout=10)
            response.raise_for_status()
            return response.text
        except Exception as e:
            logging.error(f"Error fetching JavaScript content from {js_url}: {str(e)}")
            return ""

    def scan_url(self, url: str) -> dict:
        """Main scanning function"""
        results = {
            'url': url,
            'scan_time': datetime.now().isoformat(),
            'findings': {}
        }
        
        with Progress() as progress:
            # Step 1: Get JS files
            task1 = progress.add_task("[cyan]Finding JavaScript files...", total=1)
            js_files = self.get_js_files(url)
            progress.update(task1, completed=1)
            
            # Step 2: Scan each file
            task2 = progress.add_task("[green]Scanning JavaScript files...", total=len(js_files))
            
            for js_type, js_content in js_files:
                if js_type == 'external':
                    content = self.fetch_js_content(js_content)
                else:
                    content = js_content
                
                findings = self.scan_content(content)
                if findings:
                    results['findings'][js_content] = findings
                
                progress.update(task2, advance=1)
        
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

