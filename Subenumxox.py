#!/usr/bin/env python3
"""
🚀 SUBENUM PRO - Advanced Subdomain Enumeration Tool
Monster Edition - 1000+ Lines of Pure Recon Power
"""

import argparse
import asyncio
import concurrent.futures
import dns.resolver
import dns.asyncresolver
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib3
import random
import hashlib
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from datetime import datetime
from typing import List, Set, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

# Third-party imports
try:
    import requests
    from bs4 import BeautifulSoup
    import colorama
    from colorama import Fore, Style, Back
    import tldextract
    from fake_useragent import UserAgent
    import pyfiglet
    import aiohttp
    import asyncio_throttle
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.markdown import Markdown
    from rich.layout import Layout
    import nmap
    import threading
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("💡 Please run: pip install requests beautifulsoup4 colorama tldextract fake-useragent pyfiglet aiohttp asyncio-throttle rich python-nmap cryptography")
    sys.exit(1)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
colorama.init(autoreset=True)

class ScanType(Enum):
    DNS_BRUTEFORCE = "dns_bruteforce"
    CT_LOGS = "certificate_transparency"
    WEB_CRAWLING = "web_crawling"
    SEARCH_ENGINES = "search_engines"
    DNS_ZONE_TRANSFER = "dns_zone_transfer"
    SAN_ANALYSIS = "san_analysis"
    PERMUTATIONS = "permutations"

@dataclass
class SubdomainResult:
    subdomain: str
    ips: List[str]
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = None
    response_time: Optional[float] = None
    ssl_info: Optional[Dict] = None
    ports: List[int] = None
    screenshot_path: Optional[str] = None

    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []
        if self.ports is None:
            self.ports = []

class Config:
    def __init__(self):
        self.timeout = 15
        self.max_workers = 100
        self.max_async_tasks = 200
        self.user_agent = UserAgent()
        self.dns_resolvers = [
            '8.8.8.8', '1.1.1.1', '9.9.9.9', '8.8.4.4', '1.0.0.1',
            '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6'
        ]
        
        # Extended subdomains wordlist (500+ entries)
        self.common_subdomains = self._load_extended_wordlist()
        
        # Technology signatures
        self.tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'media/jui'],
            'Drupal': ['drupal', 'sites/all'],
            'Apache': ['Apache', 'apache'],
            'Nginx': ['nginx'],
            'IIS': ['Microsoft-IIS', 'IIS'],
            'CloudFlare': ['cloudflare'],
            'AWS': ['aws', 'amazon'],
            'Google Cloud': ['google', 'gws'],
            'PHP': ['PHP', 'X-Powered-By: PHP'],
            'ASP.NET': ['ASP.NET', 'X-Powered-By: ASP.NET'],
            'Node.js': ['Node.js', 'X-Powered-By: Express'],
            'React': ['react', 'React'],
            'Vue.js': ['vue', 'Vue.js'],
            'Angular': ['angular', 'ng-'],
        }
        
        # Common ports for scanning
        self.common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995, 8080, 8443, 3000, 5000, 8000, 9000]

    def _load_extended_wordlist(self) -> List[str]:
        """Load extended wordlist with common subdomains"""
        base_words = [
            # Infrastructure
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'email', 'owa',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2', 'cdn', 'cdn1', 'cdn2',
            'vpn', 'ssh', 'remote', 'admin', 'administrator', 'login', 'signin',
            'api', 'api1', 'api2', 'api3', 'rest', 'graphql', 'soap',
            'dev', 'development', 'test', 'testing', 'qa', 'staging', 'preprod',
            'prod', 'production', 'live', 'demo', 'sandbox',
            'backup', 'backups', 'archive', 'old', 'new', 'temp', 'tmp',
            
            # Services
            'blog', 'news', 'forum', 'forums', 'community', 'support', 'help',
            'docs', 'documentation', 'wiki', 'kb', 'knowledgebase',
            'shop', 'store', 'ecommerce', 'cart', 'checkout', 'payment',
            'app', 'apps', 'mobile', 'm', 'portal', 'dashboard', 'cp',
            'cpanel', 'whm', 'plesk', 'webmin', 'directadmin',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
            'files', 'file', 'download', 'uploads', 'media', 'static',
            'assets', 'images', 'img', 'video', 'audio', 'cdn',
            
            # Geographic
            'us', 'uk', 'eu', 'de', 'fr', 'jp', 'cn', 'in', 'au', 'ca',
            'ny', 'nyc', 'sf', 'la', 'chi', 'lon', 'tokyo', 'beijing',
            'north', 'south', 'east', 'west', 'central',
            
            # Cloud & Infrastructure
            'aws', 'azure', 'gcp', 'cloud', 'storage', 'bucket',
            'lb', 'loadbalancer', 'haproxy', 'proxy',
            'monitor', 'monitoring', 'metrics', 'grafana', 'prometheus',
            'log', 'logs', 'logging', 'kibana', 'elk',
            
            # Development
            'git', 'github', 'gitlab', 'svn', 'jenkins', 'jenkinsci',
            'docker', 'kubernetes', 'k8s', 'registry',
            'ci', 'cd', 'build', 'deploy', 'pipeline',
            
            # Security
            'secure', 'security', 'ssl', 'tls', 'cert', 'firewall',
            'waf', 'shield', 'guard', 'protect',
            
            # Business
            'careers', 'jobs', 'hr', 'recruiting', 'recruitment',
            'about', 'team', 'company', 'corporate', 'business',
            'contact', 'contacts', 'info', 'information',
            'services', 'solutions', 'products', 'partners',
            
            # Marketing
            'marketing', 'ads', 'advertising', 'campaign', 'promo',
            'social', 'facebook', 'twitter', 'linkedin', 'instagram',
            'events', 'webinar', 'conference',
            
            # Internal
            'internal', 'intranet', 'local', 'localhost', 'home',
            'office', 'corp', 'enterprise', 'global', 'worldwide',
            
            # Additional common patterns
            'alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta',
            'primary', 'secondary', 'tertiary', 'quaternary',
            'main', 'alt', 'alternate', 'backup', 'replica',
            'read', 'write', 'master', 'slave', 'primary', 'secondary',
            'edge', 'origin', 'source', 'destination',
            'inbound', 'outbound', 'ingress', 'egress',
            'public', 'private', 'protected', 'restricted',
        ]
        
        # Add numbered variations
        numbered_words = []
        for word in base_words:
            numbered_words.append(word)
            for i in range(10):
                numbered_words.append(f"{word}{i}")
                numbered_words.append(f"{word}-{i}")
                numbered_words.append(f"{word}_{i}")
                if i < 5:  # Add fewer variations for higher numbers
                    numbered_words.append(f"{word}0{i}")
        
        # Add common patterns
        patterns = []
        for word in base_words[:100]:  # Limit to first 100 to avoid explosion
            patterns.extend([
                f"{word}-api", f"{word}-admin", f"{word}-dev", f"{word}-test",
                f"{word}-staging", f"{word}-prod", f"{word}-live",
                f"api-{word}", f"admin-{word}", f"dev-{word}",
            ])
        
        all_words = list(set(base_words + numbered_words + patterns))
        return sorted(all_words)

class SubdomainFinder:
    def __init__(self, domain: str, config: Config):
        self.domain = domain
        self.config = config
        self.found_subdomains: Set[str] = set()
        self.results: Dict[str, SubdomainResult] = {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.config.user_agent.random})
        self.console = Console()
        self.lock = threading.Lock()
        self.scan_stats = {scan_type: 0 for scan_type in ScanType}
        
        # Create output directory
        self.output_dir = Path(f"subenum_results_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(exist_ok=True)
        
    def display_banner(self):
        """Display awesome banner"""
        banner_text = pyfiglet.figlet_format("SUBENUM PRO", font="slant")
        
        banner_panel = Panel(
            f"[bold cyan]{banner_text}[/bold cyan]\n"
            f"[bold yellow]🚀 Advanced Subdomain Enumeration Tool[/bold yellow]\n"
            f"[bold green]📡 Target: {self.domain}[/bold green]\n"
            f"[bold white]⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold white]",
            style="bold blue",
            padding=1
        )
        
        self.console.print(banner_panel)
        
        # System info
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Key", style="cyan")
        info_table.add_column("Value", style="white")
        
        info_table.add_row("Threads", f"{self.config.max_workers}")
        info_table.add_row("Wordlist Size", f"{len(self.config.common_subdomains)}")
        info_table.add_row("DNS Resolvers", f"{len(self.config.dns_resolvers)}")
        info_table.add_row("Output Directory", f"{self.output_dir}")
        
        self.console.print(Panel(info_table, title="⚙️ Configuration", style="green"))

    async def resolve_dns_async(self, subdomain: str) -> List[str]:
        """Asynchronously resolve DNS A records"""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = self.config.dns_resolvers
            answers = await resolver.resolve(subdomain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def dns_bruteforce_async(self):
        """Asynchronous DNS bruteforce attack"""
        self.console.print(f"\n[bold cyan]🔍 Starting DNS Bruteforce (Async)...[/bold cyan]")
        
        candidates = set()
        for word in self.config.common_subdomains:
            candidates.add(f"{word}.{self.domain}")
        
        total = len(candidates)
        semaphore = asyncio.Semaphore(self.config.max_async_tasks)
        
        async def check_subdomain(subdomain: str):
            async with semaphore:
                ips = await self.resolve_dns_async(subdomain)
                if ips:
                    with self.lock:
                        self.found_subdomains.add(subdomain)
                        self.scan_stats[ScanType.DNS_BRUTEFORCE] += 1
                    self.console.print(f"[green]✓ {subdomain} → {', '.join(ips)}[/green]")
                    return subdomain, ips
                return None
        
        tasks = [check_subdomain(sub) for sub in candidates]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Bruteforcing...", total=total)
            
            for batch in self._chunk_list(tasks, 100):
                results = await asyncio.gather(*batch, return_exceptions=True)
                progress.update(task, advance=len(batch))
                
                for result in results:
                    if isinstance(result, Exception):
                        continue
        
        self.console.print(f"[bold green]✅ DNS Bruteforce completed: {self.scan_stats[ScanType.DNS_BRUTEFORCE]} found[/bold green]")

    def dns_zone_transfer(self):
        """Attempt DNS zone transfer"""
        self.console.print(f"\n[bold cyan]🌐 Attempting DNS Zone Transfer...[/bold cyan]")
        
        nameservers = []
        try:
            answers = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns.target) for ns in answers]
        except Exception as e:
            self.console.print(f"[yellow]⚠️ Could not find nameservers: {e}[/yellow]")
            return
        
        for ns in nameservers:
            try:
                self.console.print(f"[white]Trying zone transfer from {ns}[/white]")
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(ns)]
                
                try:
                    zone = resolver.resolve(self.domain, 'AXFR')
                    for record in zone:
                        if 'IN A' in str(record):
                            subdomain = str(record).split()[0]
                            if subdomain.endswith('.'):
                                subdomain = subdomain[:-1]
                            if subdomain not in self.found_subdomains:
                                self.found_subdomains.add(subdomain)
                                self.scan_stats[ScanType.DNS_ZONE_TRANSFER] += 1
                                self.console.print(f"[green]🎯 Zone Transfer: {subdomain}[/green]")
                except Exception as e:
                    self.console.print(f"[yellow]Zone transfer failed on {ns}: {e}[/yellow]")
                    
            except Exception as e:
                self.console.print(f"[red]Error with {ns}: {e}[/red]")

    async def certificate_transparency_async(self):
        """Get subdomains from certificate transparency logs (multiple sources)"""
        self.console.print(f"\n[bold cyan]📜 Checking Certificate Transparency Logs...[/bold cyan]")
        
        sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://crt.sh/?q=%25.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names",
        ]
        
        found = set()
        
        async with aiohttp.ClientSession() as session:
            for url in sources:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            if 'crt.sh' in url:
                                for entry in data:
                                    # Process common_name
                                    name = entry.get('common_name', '').lower().strip()
                                    if name and self.domain in name and '*' not in name:
                                        found.add(name)
                                    
                                    # Process name_value
                                    name_value = entry.get('name_value', '').lower()
                                    if name_value:
                                        for name in name_value.split('\n'):
                                            name = name.strip()
                                            if name and self.domain in name and '*' not in name:
                                                found.add(name)
                            
                            elif 'certspotter' in url:
                                for entry in data:
                                    for dns_name in entry.get('dns_names', []):
                                        if self.domain in dns_name and '*' not in dns_name:
                                            found.add(dns_name.lower())
                
                except Exception as e:
                    self.console.print(f"[yellow]⚠️ CT source {url} failed: {e}[/yellow]")
        
        new_domains = found - self.found_subdomains
        for domain in new_domains:
            self.found_subdomains.add(domain)
            self.scan_stats[ScanType.CT_LOGS] += 1
            self.console.print(f"[green]📜 CT Log: {domain}[/green]")
        
        self.console.print(f"[bold green]✅ CT Logs completed: {len(new_domains)} new subdomains[/bold green]")

    def analyze_ssl_certificates(self):
        """Analyze SSL certificates for SAN entries"""
        self.console.print(f"\n[bold cyan]🔐 Analyzing SSL Certificates...[/bold cyan]")
        
        found = set()
        
        def get_ssl_sans(hostname: str, port: int = 443):
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                        
                        # Get Subject Alternative Names
                        sans = []
                        try:
                            ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                            sans = ext.value.get_values_for_type(x509.DNSName)
                        except x509.ExtensionNotFound:
                            pass
                        
                        return sans
            except Exception:
                return []
        
        # Check main domain and found subdomains
        targets = [self.domain] + list(self.found_subdomains)[:20]  # Limit to first 20
        
        for target in targets:
            try:
                sans = get_ssl_sans(target)
                for san in sans:
                    if self.domain in san and san not in self.found_subdomains and '*' not in san:
                        found.add(san)
                        self.console.print(f"[green]🔐 SAN Found: {san}[/green]")
            except Exception as e:
                continue
        
        for domain in found:
            self.found_subdomains.add(domain)
            self.scan_stats[ScanType.SAN_ANALYSIS] += 1
        
        self.console.print(f"[bold green]✅ SSL Analysis completed: {len(found)} new subdomains[/bold green]")

    async def web_crawling_discovery(self):
        """Discover subdomains through web crawling"""
        self.console.print(f"\n[bold cyan]🕷️ Web Crawling for Subdomains...[/bold cyan]")
        
        found = set()
        
        async def crawl_url(url: str):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as response:
                        if response.status == 200:
                            text = await response.text()
                            
                            # Find subdomains in text content
                            pattern = rf'[a-zA-Z0-9][a-zA-Z0-9.-]*\.{re.escape(self.domain)}'
                            matches = re.findall(pattern, text)
                            
                            for match in matches:
                                if match not in self.found_subdomains:
                                    found.add(match)
                                    self.console.print(f"[green]🕷️ Crawled: {match}[/green]")
            except Exception:
                pass
        
        # Crawl found subdomains that have web servers
        targets = []
        for subdomain in list(self.found_subdomains)[:50]:  # Limit crawling
            for scheme in ['https', 'http']:
                targets.append(f"{scheme}://{subdomain}")
        
        tasks = [crawl_url(url) for url in targets]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Crawling...", total=len(tasks))
            
            for batch in self._chunk_list(tasks, 20):
                await asyncio.gather(*batch, return_exceptions=True)
                progress.update(task, advance=len(batch))
        
        for domain in found:
            self.found_subdomains.add(domain)
            self.scan_stats[ScanType.WEB_CRAWLING] += 1
        
        self.console.print(f"[bold green]✅ Web Crawling completed: {len(found)} new subdomains[/bold green]")

    def generate_permutations(self):
        """Generate subdomain permutations"""
        self.console.print(f"\n[bold cyan]🔄 Generating Permutations...[/bold cyan]")
        
        found = set()
        base_domains = list(self.found_subdomains)[:100]  # Use first 100 as base
        
        for base in base_domains:
            # Remove domain part to get subdomain
            sub_part = base.replace(f".{self.domain}", "")
            
            # Generate permutations
            permutations = [
                f"dev-{sub_part}.{self.domain}",
                f"test-{sub_part}.{self.domain}",
                f"staging-{sub_part}.{self.domain}",
                f"prod-{sub_part}.{self.domain}",
                f"api-{sub_part}.{self.domain}",
                f"admin-{sub_part}.{self.domain}",
                f"mobile-{sub_part}.{self.domain}",
                f"app-{sub_part}.{self.domain}",
                f"cdn-{sub_part}.{self.domain}",
                f"static-{sub_part}.{self.domain}",
            ]
            
            # Check permutations
            for perm in permutations:
                if perm not in self.found_subdomains:
                    ips = self.resolve_dns(perm)
                    if ips:
                        found.add(perm)
                        self.console.print(f"[green]🔄 Permutation: {perm}[/green]")
        
        for domain in found:
            self.found_subdomains.add(domain)
            self.scan_stats[ScanType.PERMUTATIONS] += 1
        
        self.console.print(f"[bold green]✅ Permutations completed: {len(found)} new subdomains[/bold green]")

    def resolve_dns(self, subdomain: str) -> List[str]:
        """Synchronous DNS resolution"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.config.dns_resolvers
            resolver.timeout = self.config.timeout
            resolver.lifetime = self.config.timeout
            
            answers = resolver.resolve(subdomain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def comprehensive_scan(self):
        """Run comprehensive subdomain discovery"""
        self.display_banner()
        
        # Run all discovery methods
        await self.dns_bruteforce_async()
        self.dns_zone_transfer()
        await self.certificate_transparency_async()
        self.analyze_ssl_certificates()
        await self.web_crawling_discovery()
        self.generate_permutations()
        
        # Perform detailed reconnaissance
        await self.detailed_reconnaissance()

    async def check_http_async(self, subdomain: str) -> Dict[str, Any]:
        """Asynchronous HTTP check"""
        info = {'status': None, 'title': None, 'server': None, 'response_time': None, 'technologies': []}
        
        async with aiohttp.ClientSession() as session:
            for scheme in ['https', 'http']:
                url = f"{scheme}://{subdomain}"
                try:
                    start_time = time.time()
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                        response_time = time.time() - start_time
                        
                        info['status'] = response.status
                        info['server'] = response.headers.get('Server', '')
                        info['response_time'] = response_time
                        
                        # Detect technologies
                        text = await response.text()
                        info['technologies'] = self.detect_technologies(text, response.headers)
                        
                        # Extract title
                        soup = BeautifulSoup(text, 'html.parser')
                        if soup.title and soup.title.string:
                            info['title'] = soup.title.string.strip()[:100]
                        
                        break
                except Exception:
                    continue
        
        return info

    def detect_technologies(self, html: str, headers: Dict) -> List[str]:
        """Detect web technologies"""
        technologies = []
        
        # Check headers
        server = headers.get('Server', '').lower()
        for tech, patterns in self.config.tech_signatures.items():
            for pattern in patterns:
                if pattern.lower() in server:
                    technologies.append(tech)
                    break
        
        # Check HTML content
        html_lower = html.lower()
        for tech, patterns in self.config.tech_signatures.items():
            for pattern in patterns:
                if pattern.lower() in html_lower and tech not in technologies:
                    technologies.append(tech)
                    break
        
        return list(set(technologies))

    def port_scan(self, subdomain: str) -> List[int]:
        """Quick port scan for common ports"""
        open_ports = []
        
        try:
            nm = nmap.PortScanner()
            # Scan top ports quickly
            result = nm.scan(subdomain, arguments='-T4 --top-ports 50')
            
            if subdomain in result['scan']:
                for port in result['scan'][subdomain]['tcp']:
                    if result['scan'][subdomain]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)
        except Exception:
            # Fallback to socket scanning
            for port in self.config.common_ports[:20]:  # Limit to first 20 ports
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((subdomain, port))
                    sock.close()
                    if result == 0:
                        open_ports.append(port)
                except Exception:
                    pass
        
        return open_ports

    async def detailed_reconnaissance(self):
        """Perform detailed reconnaissance on found subdomains"""
        if not self.found_subdomains:
            return
        
        self.console.print(f"\n[bold cyan]🔬 Performing Detailed Reconnaissance...[/bold cyan]")
        
        subdomains_list = list(self.found_subdomains)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
        ) as progress:
            recon_task = progress.add_task("[cyan]Reconnaissance...", total=len(subdomains_list))
            
            async def process_subdomain(subdomain: str):
                try:
                    # DNS resolution
                    ips = await self.resolve_dns_async(subdomain)
                    
                    # HTTP check
                    http_info = await self.check_http_async(subdomain)
                    
                    # Port scan (limited to first 50 subdomains)
                    ports = []
                    if subdomains_list.index(subdomain) < 50:
                        ports = await asyncio.get_event_loop().run_in_executor(
                            None, self.port_scan, subdomain
                        )
                    
                    # Create result object
                    result = SubdomainResult(
                        subdomain=subdomain,
                        ips=ips,
                        status_code=http_info['status'],
                        title=http_info['title'],
                        server=http_info['server'],
                        technologies=http_info['technologies'],
                        response_time=http_info['response_time'],
                        ports=ports
                    )
                    
                    self.results[subdomain] = result
                    
                    # Display result
                    self.display_subdomain_result(result)
                    
                except Exception as e:
                    self.console.print(f"[yellow]⚠️ Recon failed for {subdomain}: {e}[/yellow]")
                finally:
                    progress.update(recon_task, advance=1)
            
            # Process in batches
            semaphore = asyncio.Semaphore(50)
            
            async def process_with_semaphore(subdomain):
                async with semaphore:
                    await process_subdomain(subdomain)
            
            tasks = [process_with_semaphore(sub) for sub in subdomains_list]
            await asyncio.gather(*tasks, return_exceptions=True)

    def display_subdomain_result(self, result: SubdomainResult):
        """Display individual subdomain result"""
        status_color = "green" if result.status_code == 200 else "yellow" if result.status_code else "red"
        status_text = str(result.status_code) if result.status_code else "No HTTP"
        
        # Create a compact display
        tech_str = ", ".join(result.technologies[:3]) if result.technologies else "Unknown"
        ports_str = ", ".join(map(str, result.ports[:5])) if result.ports else "None"
        
        self.console.print(
            f"[white]{result.subdomain:<40}[/white] "
            f"[{status_color}]{status_text:<8}[/{status_color}] "
            f"[cyan]{result.server[:20]:<20}[/cyan] "
            f"[magenta]{tech_str:<30}[/magenta] "
            f"[yellow]{ports_str:<20}[/yellow]"
        )

    def display_final_results(self):
        """Display comprehensive results"""
        self.console.print(f"\n{'='*80}")
        self.console.print("[bold green]🎉 SCAN COMPLETED![/bold green]")
        self.console.print(f"{'='*80}")
        
        # Statistics
        stats_table = Table(title="📊 Scan Statistics", show_header=True, header_style="bold magenta")
        stats_table.add_column("Method", style="cyan")
        stats_table.add_column("Subdomains Found", style="green")
        
        for scan_type, count in self.scan_stats.items():
            if count > 0:
                stats_table.add_row(scan_type.value.replace('_', ' ').title(), str(count))
        
        stats_table.add_row("TOTAL", str(len(self.found_subdomains)), style="bold yellow")
        self.console.print(stats_table)
        
        # Results table
        results_table = Table(title=f"🎯 Found Subdomains ({len(self.found_subdomains)})", show_header=True, header_style="bold blue")
        results_table.add_column("Subdomain", style="white")
        results_table.add_column("IPs", style="cyan")
        results_table.add_column("Status", style="green")
        results_table.add_column("Server", style="yellow")
        results_table.add_column("Technologies", style="magenta")
        
        for subdomain, result in sorted(self.results.items())[:50]:  # Show first 50
            ips_str = ", ".join(result.ips[:2]) if result.ips else "No DNS"
            status = str(result.status_code) if result.status_code else "No HTTP"
            server = result.server[:20] + "..." if result.server and len(result.server) > 20 else result.server or "Unknown"
            tech = ", ".join(result.technologies[:2]) if result.technologies else "Unknown"
            
            results_table.add_row(subdomain, ips_str, status, server, tech)
        
        self.console.print(results_table)
        
        if len(self.results) > 50:
            self.console.print(f"[yellow]... and {len(self.results) - 50} more subdomains[/yellow]")

    def save_results(self):
        """Save all results to files"""
        # Save simple list
        txt_file = self.output_dir / f"subdomains_{self.domain}.txt"
        with open(txt_file, 'w') as f:
            for subdomain in sorted(self.found_subdomains):
                f.write(subdomain + '\n')
        
        # Save detailed JSON
        json_file = self.output_dir / f"subdomains_{self.domain}_detailed.json"
        detailed_results = {}
        for subdomain, result in self.results.items():
            detailed_results[subdomain] = {
                'ips': result.ips,
                'status_code': result.status_code,
                'title': result.title,
                'server': result.server,
                'technologies': result.technologies,
                'response_time': result.response_time,
                'ports': result.ports
            }
        
        with open(json_file, 'w') as f:
            json.dump(detailed_results, f, indent=2, default=str)
        
        # Save statistics
        stats_file = self.output_dir / f"scan_statistics.json"
        with open(stats_file, 'w') as f:
            json.dump({
                'domain': self.domain,
                'total_subdomains': len(self.found_subdomains),
                'scan_stats': {k.value: v for k, v in self.scan_stats.items()},
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        
        # Save in various formats
        self._save_additional_formats()
        
        self.console.print(f"\n[bold green]💾 Results saved to: {self.output_dir}/[/bold green]")
        self.console.print(f"[green]   📄 Subdomains list: {txt_file}[/green]")
        self.console.print(f"[green]   📊 Detailed results: {json_file}[/green]")
        self.console.print(f"[green]   📈 Statistics: {stats_file}[/green]")

    def _save_additional_formats(self):
        """Save results in additional formats"""
        # CSV format
        csv_file = self.output_dir / f"subdomains_{self.domain}.csv"
        with open(csv_file, 'w') as f:
            f.write("Subdomain,IPs,Status,Title,Server,Technologies,ResponseTime,Ports\n")
            for subdomain, result in self.results.items():
                ips_str = ";".join(result.ips) if result.ips else ""
                status = result.status_code or ""
                title = (result.title or "").replace('"', '""')
                server = (result.server or "").replace('"', '""')
                tech_str = ";".join(result.technologies) if result.technologies else ""
                response_time = result.response_time or ""
                ports_str = ";".join(map(str, result.ports)) if result.ports else ""
                
                f.write(f'"{subdomain}","{ips_str}","{status}","{title}","{server}","{tech_str}","{response_time}","{ports_str}"\n')
        
        # Markdown report
        md_file = self.output_dir / f"REPORT_{self.domain}.md"
        with open(md_file, 'w') as f:
            f.write(f"# Subdomain Enumeration Report: {self.domain}\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Total Subdomains Found:** {len(self.found_subdomains)}\n\n")
            
            f.write("## Scan Statistics\n")
            for scan_type, count in self.scan_stats.items():
                if count > 0:
                    f.write(f"- **{scan_type.value.replace('_', ' ').title()}:** {count}\n")
            
            f.write("\n## Subdomains\n")
            f.write("| Subdomain | IPs | Status | Server | Technologies |\n")
            f.write("|-----------|-----|--------|--------|--------------|\n")
            
            for subdomain, result in sorted(self.results.items())[:100]:  # First 100 in markdown
                ips_str = ", ".join(result.ips[:2]) if result.ips else ""
                status = result.status_code or "N/A"
                server = result.server or "N/A"
                tech_str = ", ".join(result.technologies[:3]) if result.technologies else "N/A"
                
                f.write(f"| {subdomain} | {ips_str} | {status} | {server} | {tech_str} |\n")

    def _chunk_list(self, lst: List, chunk_size: int) -> List[List]:
        """Split list into chunks"""
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

async def main():
    parser = argparse.ArgumentParser(description="🚀 SUBENUM PRO - Advanced Subdomain Enumeration Tool")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--no-recon", action="store_true", help="Skip detailed reconnaissance")
    parser.add_argument("--quick", action="store_true", help="Quick scan (DNS bruteforce only)")
    
    args = parser.parse_args()
    
    # Configuration
    config = Config()
    config.max_workers = args.threads
    
    # Load custom wordlist if provided
    if args.wordlist and os.path.exists(args.wordlist):
        try:
            with open(args.wordlist, 'r') as f:
                custom_words = [line.strip() for line in f if line.strip()]
            config.common_subdomains.extend(custom_words)
            print(f"[+] Loaded {len(custom_words)} words from {args.wordlist}")
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")
    
    # Initialize finder
    finder = SubdomainFinder(args.domain, config)
    
    if args.output:
        finder.output_dir = Path(args.output)
        finder.output_dir.mkdir(exist_ok=True)
    
    try:
        if args.quick:
            # Quick scan - DNS bruteforce only
            await finder.dns_bruteforce_async()
        else:
            # Comprehensive scan
            await finder.comprehensive_scan()
        
        # Save results
        finder.save_results()
        
        # Display final results
        finder.display_final_results()
        
    except KeyboardInterrupt:
        finder.console.print(f"\n[bold yellow]⚠️ Scan interrupted by user[/bold yellow]")
        if finder.found_subdomains:
            finder.save_results()
    except Exception as e:
        finder.console.print(f"[bold red]💥 Error: {e}[/bold red]")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Check if running with proper permissions
    if os.name != 'nt' and os.geteuid() == 0:
        print("🔒 Running with root privileges - some features may work better")
    
    # Run the main function
    asyncio.run(main())
