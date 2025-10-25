"""
Information Gathering Tools Module
"""
import subprocess
import socket
import ssl
import whois
import dns.resolver
import requests
import json
from datetime import datetime
import re

class InfoGatheringTools:
    """Advanced information gathering tools"""
    
    def __init__(self):
        self.available_tools = self.check_additional_tools()
    
    def check_additional_tools(self):
        """Check which additional tools are installed"""
        tools = {
            'whois': {'installed': True, 'description': 'Domain registration info'},
            'dnslookup': {'installed': True, 'description': 'DNS records lookup'},
            'sslcheck': {'installed': True, 'description': 'SSL/TLS certificate check'},
            'sublist3r': {'installed': False, 'description': 'Subdomain enumeration'},
            'theharvester': {'installed': False, 'description': 'Email & subdomain harvester'},
            'fierce': {'installed': False, 'description': 'DNS reconnaissance'},
            'wafw00f': {'installed': False, 'description': 'WAF detection'},
            'httpx': {'installed': False, 'description': 'HTTP probe'},
        }
        
        # Check external tools
        for tool in ['sublist3r', 'theharvester', 'fierce', 'wafw00f', 'httpx']:
            try:
                result = subprocess.run([tool, '-h'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 or 'usage' in result.stdout.lower():
                    tools[tool]['installed'] = True
            except:
                pass
        
        return tools
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(domain)
            output = f"""
═══════════════════════════════════════
    WHOIS INFORMATION FOR {domain}
═══════════════════════════════════════

Domain Name: {w.domain_name}
Registrar: {w.registrar}
Creation Date: {w.creation_date}
Expiration Date: {w.expiration_date}
Updated Date: {w.updated_date}

Name Servers:
{chr(10).join(f'  • {ns}' for ns in (w.name_servers or [])) if w.name_servers else '  None found'}

Status: {w.status}

Registrant:
  Organization: {w.org if hasattr(w, 'org') else 'N/A'}
  Country: {w.country if hasattr(w, 'country') else 'N/A'}
  Email: {w.emails if hasattr(w, 'emails') else 'N/A'}

═══════════════════════════════════════
"""
            return {'success': True, 'output': output, 'data': w}
        except Exception as e:
            return {'success': False, 'error': str(e), 'output': f'WHOIS lookup failed: {str(e)}'}
    
    def dns_lookup(self, domain, intensity='medium'):
        """Perform DNS lookup with multiple record types"""
        try:
            record_types = {
                'low': ['A', 'MX'],
                'medium': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'],
                'deep': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']
            }
            
            records_to_check = record_types.get(intensity, record_types['medium'])
            results = []
            
            output = f"""
═══════════════════════════════════════
    DNS RECORDS FOR {domain}
═══════════════════════════════════════

"""
            
            for record_type in records_to_check:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    output += f"\n{record_type} Records:\n"
                    for rdata in answers:
                        output += f"  • {rdata}\n"
                        results.append({'type': record_type, 'value': str(rdata)})
                except dns.resolver.NoAnswer:
                    output += f"\n{record_type} Records: No records found\n"
                except dns.resolver.NXDOMAIN:
                    output += f"\n{record_type} Records: Domain does not exist\n"
                except Exception as e:
                    output += f"\n{record_type} Records: Error - {str(e)}\n"
            
            output += "\n═══════════════════════════════════════\n"
            
            return {'success': True, 'output': output, 'data': results}
        except Exception as e:
            return {'success': False, 'error': str(e), 'output': f'DNS lookup failed: {str(e)}'}
    
    def ssl_check(self, hostname, port=443):
        """Check SSL/TLS certificate"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            output = f"""
═══════════════════════════════════════
    SSL/TLS CERTIFICATE CHECK
    Target: {hostname}:{port}
═══════════════════════════════════════

Certificate Information:
  Subject: {dict(x[0] for x in cert['subject'])}
  Issuer: {dict(x[0] for x in cert['issuer'])}
  Version: {cert.get('version', 'N/A')}
  Serial Number: {cert.get('serialNumber', 'N/A')}
  
Valid From: {cert.get('notBefore', 'N/A')}
Valid Until: {cert.get('notAfter', 'N/A')}

Subject Alternative Names:
{chr(10).join(f'  • {name[1]}' for name in cert.get('subjectAltName', [])) if cert.get('subjectAltName') else '  None'}

TLS Configuration:
  Protocol Version: {version}
  Cipher Suite: {cipher[0]} ({cipher[1]}-bit)
  
Certificate Chain:
  Verified: ✓ Valid certificate chain

═══════════════════════════════════════
"""
            
            return {'success': True, 'output': output, 'data': cert}
        except Exception as e:
            return {'success': False, 'error': str(e), 'output': f'SSL check failed: {str(e)}'}
    
    def http_headers(self, url):
        """Analyze HTTP headers"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            # ✅ Add realistic headers to bypass WAF/security filters
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=False)
            
            output = f"""
═══════════════════════════════════════
    HTTP HEADERS ANALYSIS
    URL: {url}
═══════════════════════════════════════

Status Code: {response.status_code} {response.reason}
Final URL: {response.url}

Response Headers:
"""
            for header, value in response.headers.items():
                output += f"  {header}: {value}\n"
            
            # Security headers check
            output += "\n═══ Security Headers Analysis ═══\n\n"
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'Content-Security-Policy': 'CSP',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy'
            }
            
            for header, description in security_headers.items():
                if header in response.headers:
                    output += f"  ✓ {description}: {response.headers[header]}\n"
                else:
                    output += f"  ✗ {description}: Missing\n"
            
            output += "\n═══════════════════════════════════════\n"
            
            return {'success': True, 'output': output, 'data': dict(response.headers)}
        except Exception as e:
            return {'success': False, 'error': str(e), 'output': f'HTTP headers check failed: {str(e)}'}
    
    def port_scan_quick(self, target, ports=None):
        """Quick port scan using Python socket"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        output = f"""
═══════════════════════════════════════
    QUICK PORT SCAN
    Target: {target}
═══════════════════════════════════════

Scanning {len(ports)} common ports...

"""
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                output += f"  ✓ Port {port}: OPEN\n"
                open_ports.append(port)
            else:
                output += f"  ✗ Port {port}: Closed\n"
        
        output += f"\n═══════════════════════════════════════\n"
        output += f"Summary: {len(open_ports)} open ports found\n"
        output += f"═══════════════════════════════════════\n"
        
        return {'success': True, 'output': output, 'data': {'open_ports': open_ports}}
    
    def run_theharvester(self, domain, intensity='medium'):
        """Run theHarvester for email and subdomain enumeration"""
        intensity_flags = {
            'low': ['-d', domain, '-b', 'google', '-l', '100'],
            'medium': ['-d', domain, '-b', 'google,bing', '-l', '300'],
            'deep': ['-d', domain, '-b', 'all', '-l', '500']
        }
        
        flags = intensity_flags.get(intensity, intensity_flags['medium'])
        cmd = ['theHarvester'] + flags
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {'success': True, 'output': result.stdout, 'error': result.stderr}
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '', 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}
    
    def run_sublist3r(self, domain):
        """Run Sublist3r for subdomain enumeration"""
        cmd = ['sublist3r', '-d', domain]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {'success': True, 'output': result.stdout, 'error': result.stderr}
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '', 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}
