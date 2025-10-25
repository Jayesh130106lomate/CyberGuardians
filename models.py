"""
models.py - Data models and core classes for the security scanner
"""
import subprocess
import re
import os
from ai_analyzer import AISecurityAnalyzer
from info_gathering import InfoGatheringTools

class SecurityScanner:
    """Main security scanning class"""

    def __init__(self):
        self.info_tools = InfoGatheringTools()
        self.available_tools = self.check_tools()
        self.ai_analyzer = None

    def check_tools(self):
        """Check which security tools are installed"""
        tools = {
            'nmap': {'installed': False, 'version': '', 'description': 'Network scanner', 'category': 'network'},
            'wpscan': {'installed': False, 'version': '', 'description': 'WordPress security scanner', 'category': 'web'},
            'nikto': {'installed': False, 'version': '', 'description': 'Web server scanner', 'category': 'web'},
            'sqlmap': {'installed': False, 'version': '', 'description': 'SQL injection scanner', 'category': 'web'},
            'dirb': {'installed': False, 'version': '', 'description': 'Directory brute force', 'category': 'web'},
            'masscan': {'installed': False, 'version': '', 'description': 'Fast port scanner', 'category': 'network'},
            'whatweb': {'installed': False, 'version': '', 'description': 'Web technology scanner', 'category': 'web'},
            'whois': {'installed': True, 'version': 'Built-in', 'description': 'Domain registration info', 'category': 'recon'},
            'dnslookup': {'installed': True, 'version': 'Built-in', 'description': 'DNS records lookup', 'category': 'recon'},
            'sslcheck': {'installed': True, 'version': 'Built-in', 'description': 'SSL/TLS certificate check', 'category': 'recon'},
            'httpheaders': {'installed': True, 'version': 'Built-in', 'description': 'HTTP headers analysis', 'category': 'recon'},
            'portscan': {'installed': True, 'version': 'Built-in', 'description': 'Quick port scanner', 'category': 'network'},
        }

        # Check external tools
        for tool, info in tools.items():
            if tool in ['whois', 'dnslookup', 'sslcheck', 'httpheaders', 'portscan']:
                continue  # Skip built-in tools

            try:
                if tool == 'nmap':
                    result = subprocess.run(['nmap', '--version'],
                                          capture_output=True, text=True, timeout=5)
                elif tool == 'wpscan':
                    result = subprocess.run(['wpscan', '--version'],
                                          capture_output=True, text=True, timeout=5)
                elif tool == 'nikto':
                    result = subprocess.run(['nikto', '-Version'],
                                          capture_output=True, text=True, timeout=5)
                elif tool == 'sqlmap':
                    result = subprocess.run(['sqlmap', '--version'],
                                          capture_output=True, text=True, timeout=5)
                elif tool == 'dirb':
                    result = subprocess.run(['dirb'],
                                          capture_output=True, text=True, timeout=5)
                elif tool == 'masscan':
                    result = subprocess.run(['masscan', '--version'],
                                          capture_output=True, text=True, timeout=5)
                elif tool == 'whatweb':
                    result = subprocess.run(['whatweb', '--version'],
                                          capture_output=True, text=True, timeout=5)

                if result.returncode == 0 or tool == 'dirb':
                    tools[tool]['installed'] = True
                    version_match = re.search(r'(\d+\.[\d.]+)', result.stdout + result.stderr)
                    if version_match:
                        tools[tool]['version'] = version_match.group(1)
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                pass

        # Add info gathering tools
        info_tools_status = self.info_tools.available_tools
        for tool, info in info_tools_status.items():
            if tool not in tools:
                tools[tool] = {
                    'installed': info['installed'],
                    'version': 'External',
                    'description': info['description'],
                    'category': 'recon'
                }

        return tools

    def stream_output(self, process, output_queue):
        """Stream process output in real-time"""
        for line in iter(process.stdout.readline, b''):
            decoded_line = line.decode('utf-8', errors='ignore')
            output_queue.put(decoded_line)
        process.stdout.close()

    def run_scan_with_streaming(self, cmd, output_queue):
        """Run scan with streaming output"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,  # Use text mode instead of binary
                bufsize=1,  # Line buffered
                universal_newlines=True
            )

            # Store process reference for stop functionality
            current_scan['current_process'] = process

            for line in iter(process.stdout.readline, ''):
                # Check if stop was requested
                if current_scan.get('stop_requested', False):
                    output_queue.put("\n🛑 Scan stopped by user\n")
                    process.kill()
                    return False

                if line:
                    output_queue.put(line)
                    current_scan['output_buffer'].append(line)  # Save for results display
                    # ✅ Accumulate output for live AI analysis
                    current_scan['accumulated_output'] += line

            process.stdout.close()
            process.wait(timeout=600)

            # Clear process reference
            current_scan['current_process'] = None

            return process.returncode == 0
        except subprocess.TimeoutExpired:
            process.kill()
            current_scan['current_process'] = None
            output_queue.put("\n⚠️ Scan timeout - process terminated\n")
            return False
        except Exception as e:
            current_scan['current_process'] = None
            output_queue.put(f"\n❌ Error: {str(e)}\n")
            return False

    def run_nmap_scan(self, target, intensity='medium', stream_output=None):
        """Run Nmap scan with different intensity levels"""
        intensity_flags = {
            'low': ['-sV', '-T2', '-p', '80,443,8080'],
            'medium': ['-sV', '-sC', '-T3', '-p', '1-1000'],
            'deep': ['-sV', '-sC', '-A', '-T4', '-p-']
        }

        flags = intensity_flags.get(intensity, intensity_flags['medium'])

        # ✅ Add stealth and evasion options
        stealth_flags = [
            '--randomize-hosts',  # Randomize target order
            '-g', '53',           # Use DNS source port (common allowed port)
            '--data-length', '25' # Add random data to packets (evade detection)
        ]

        cmd = ['nmap'] + flags + stealth_flags + [target]

        try:
            if stream_output:
                success = self.run_scan_with_streaming(cmd, stream_output)
                # Don't drain the queue here - let terminal stream handle it
                # Get output from buffer for results display
                output = ''.join(current_scan.get('output_buffer', []))
                stream_output.put("\n✓ Nmap scan completed\n")
                return {'success': success, 'output': output, 'error': ''}
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                return {
                    'success': True,
                    'output': result.stdout,
                    'error': result.stderr if result.returncode != 0 else ''
                }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '', 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}

    def run_wpscan(self, target, intensity='medium', stream_output=None):
        """Run WPScan with different intensity levels"""
        # Get WPScan API token from environment
        api_token = os.getenv('WPSCAN_API_TOKEN', '')

        intensity_flags = {
            'low': ['--url', target, '--enumerate', 'vp'],
            'medium': ['--url', target, '--enumerate', 'vp,vt,u'],
            'deep': ['--url', target, '--enumerate', 'vp,vt,tt,cb,dbe,u', '--plugins-detection', 'aggressive']
        }

        flags = intensity_flags.get(intensity, intensity_flags['medium'])

        # ✅ Add WAF bypass options - prevents 403 errors
        flags.extend([
            '--random-user-agent',      # Randomize user agent to bypass WAF
            '--throttle', '500',         # Add 500ms delay between requests (stealth mode)
            '--max-threads', '5',        # Limit concurrent requests
            '--disable-tls-checks'       # Bypass SSL/TLS verification issues
        ])

        # Add API token if available
        if api_token and api_token != 'your_wpscan_api_token_here':
            flags.extend(['--api-token', api_token])

        cmd = ['wpscan'] + flags

        try:
            if stream_output:
                success = self.run_scan_with_streaming(cmd, stream_output)
                # Don't drain the queue - let terminal stream handle it
                output = ''.join(current_scan.get('output_buffer', []))
                stream_output.put("\n✓ WPScan completed\n")
                return {'success': success, 'output': output, 'error': ''}
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                return {
                    'success': True,
                    'output': result.stdout,
                    'error': result.stderr if result.returncode != 0 else ''
                }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '', 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}

    def run_nikto_scan(self, target, intensity='medium', stream_output=None):
        """Run Nikto web server scanner"""
        intensity_flags = {
            'low': ['-h', target, '-Tuning', '1'],
            'medium': ['-h', target, '-Tuning', '123'],
            'deep': ['-h', target, '-Tuning', 'x']
        }

        flags = intensity_flags.get(intensity, intensity_flags['medium'])

        # ✅ Add evasion and stealth options
        evasion_flags = [
            '-evasion', '1',    # Random URI encoding evasion
            '-useragent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',  # Legitimate browser user agent
            '-Display', 'V',    # Verbose output
            '-timeout', '10'    # Increase timeout for slow responses
        ]

        cmd = ['nikto'] + flags + evasion_flags

        try:
            if stream_output:
                success = self.run_scan_with_streaming(cmd, stream_output)
                # Don't drain the queue - let terminal stream handle it
                output = ''.join(current_scan.get('output_buffer', []))
                stream_output.put("\n✓ Nikto scan completed\n")
                return {'success': success, 'output': output, 'error': ''}
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                return {
                    'success': True,
                    'output': result.stdout + result.stderr,
                    'error': ''
                }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '', 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}

    def run_whatweb_scan(self, target, intensity='medium', stream_output=None):
        """Run WhatWeb technology scanner"""
        intensity_flags = {
            'low': [target, '-v'],
            'medium': [target, '-v', '-a', '3'],
            'deep': [target, '-v', '-a', '4', '--log-verbose']
        }

        flags = intensity_flags.get(intensity, intensity_flags['medium'])

        # ✅ Add user agent to avoid detection
        evasion_flags = [
            '--user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '--max-threads', '5',  # Limit threads to avoid rate limiting
            '--open-timeout', '15'  # Increase timeout for slow servers
        ]

        cmd = ['whatweb'] + flags + evasion_flags

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if stream_output:
                stream_output.put(result.stdout)
            return {
                'success': True,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else ''
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': '', 'error': 'Scan timeout'}
        except Exception as e:
            return {'success': False, 'output': '', 'error': str(e)}

# Global variables for scan state (will be moved to a better location later)
current_scan = {
    "running": False,
    "progress": 0,
    "results": "",
    "terminal_output": None,
    "output_buffer": [],  # Store output for results display
    "chain_results": [],
    "current_process": None,  # Store the running process
    "stop_requested": False,   # Flag to stop scan
    "live_ai_analysis": "",   # ✅ Store live AI analysis
    "accumulated_output": ""  # ✅ Accumulate output for live AI analysis
}

# Global scan history
scan_history = []
all_scan_results = []