"""
AI-powered security analysis using Google Gemini
"""
import google.generativeai as genai
import json
from datetime import datetime
from vulnerability_intelligence import VulnerabilityIntelligence

class AISecurityAnalyzer:
    """AI analyzer for security scan results"""

    def __init__(self, api_key):
        """Initialize Gemini AI"""
        self.api_key = api_key
        self.model = None
        self._initialized = False
        self.vuln_intel = VulnerabilityIntelligence()

    def _ensure_initialized(self):
        """Lazy initialization of the AI model"""
        if self._initialized or not self.api_key:
            return

        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            # Using gemini-2.5-flash (fast, efficient, and currently available)
            self.model = genai.GenerativeModel('gemini-2.5-flash')
            self._initialized = True
        except Exception as e:
            # Silently fail during initialization - will be handled during API calls
            self.model = None
            self._initialized = False
    
    def analyze_scan_results(self, scan_data):
        """Analyze scan results using AI"""
        self._ensure_initialized()

        if not self.model:
            return {
                'error': 'AI API key not configured or network unavailable',
                'analysis': None
            }
        
        try:
            # Prepare prompt for AI analysis
            prompt = self._create_analysis_prompt(scan_data)
            
            # Get AI analysis
            response = self.model.generate_content(prompt)
            analysis = response.text
            
            return {
                'success': True,
                'analysis': analysis,
                'timestamp': datetime.now().isoformat(),
                'model': 'gemini-2.5-flash'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'analysis': None
            }
    
    def _create_analysis_prompt(self, scan_data):
        """Create detailed prompt for AI analysis"""
        prompt = f"""
You are a cybersecurity expert analyzing security scan results. Provide a comprehensive analysis in a structured format.

**SCAN INFORMATION:**
- Tool: {scan_data.get('tool', 'Unknown')}
- Target: {scan_data.get('target', 'Unknown')}
- Intensity: {scan_data.get('intensity', 'Unknown')}
- Timestamp: {scan_data.get('timestamp', 'Unknown')}

**SCAN OUTPUT:**
{scan_data.get('output', 'No output available')}

**PLEASE PROVIDE:**

1. **Executive Summary** (2-3 sentences)
   - Overall security posture
   - Critical findings overview

2. **Key Findings** (Bullet points)
   - Open ports and services
   - Vulnerabilities discovered
   - Security misconfigurations
   - Outdated software versions

3. **Risk Assessment**
   - Critical risks (High priority)
   - Medium risks (Should address)
   - Low risks (Minor issues)

4. **Recommendations** (Actionable steps)
   - Immediate actions required
   - Short-term improvements
   - Long-term security enhancements

5. **Technical Details**
   - Service versions
   - Technologies detected
   - Potential attack vectors

6. **Compliance Notes**
   - Security best practices
   - Industry standards (OWASP, CIS, etc.)

Format the response in clear sections with markdown formatting for readability.
"""
        return prompt
    
    def generate_comprehensive_report(self, all_scans, focus_areas=None):
        """Generate comprehensive report from multiple scans"""
        return self._generate_report(all_scans, 'comprehensive', focus_areas or ['vulnerabilities', 'recommendations', 'summary', 'technical'])

    def generate_session_report(self, all_scans, focus_areas=None):
        """Generate session-specific report from current session scans"""
        return self._generate_report(all_scans, 'session', focus_areas or ['vulnerabilities', 'recommendations', 'summary'])

    def generate_vulnerability_report(self, all_scans, focus_areas=None):
        """Generate vulnerability-focused report"""
        return self._generate_report(all_scans, 'vulnerabilities', focus_areas or ['vulnerabilities'])

    def generate_executive_summary(self, all_scans, focus_areas=None):
        """Generate executive summary report"""
        return self._generate_report(all_scans, 'executive', focus_areas or ['summary'])

    def generate_technical_report(self, all_scans, focus_areas=None):
        """Generate technical deep-dive report"""
        return self._generate_report(all_scans, 'technical', focus_areas or ['technical'])

    def _generate_report(self, all_scans, report_type, focus_areas):
        """Internal method to generate reports with different focuses"""
        self._ensure_initialized()

        if not self.model:
            return {
                'success': False,
                'error': 'AI API key not configured or network unavailable',
                'report': None
            }

        if not all_scans or len(all_scans) == 0:
            return {
                'success': False,
                'error': 'No scan data provided',
                'report': None
            }

        try:
            # Build concise scan data summary
            scan_details = []
            for idx, scan in enumerate(all_scans, 1):
                output = scan.get('output', 'No output')
                # Truncate very long outputs
                if len(output) > 2000:
                    output = output[:2000] + f"\n... [truncated, {len(output)-2000} more characters]"

                scan_details.append(f"""
### Scan {idx}: {scan.get('tool', 'Unknown').upper()}
- Target: {scan.get('target', 'Unknown')}
- Status: {'✓ Success' if scan.get('success') else '✗ Failed'}

**Output:**
```
{output}
```
""")

            # Get unique targets and tools
            targets = ', '.join(set(str(s.get('target', 'Unknown')) for s in all_scans))
            tools = ', '.join(set(str(s.get('tool', 'Unknown')) for s in all_scans))

            # Build focus area instructions
            focus_instructions = self._build_focus_instructions(report_type, focus_areas)

            prompt = f"""You are a Senior Cybersecurity Analyst. Analyze the following security scan data and create a professional report.

**SCAN OVERVIEW:**
- Scans: {len(all_scans)}
- Target(s): {targets}
- Tools: {tools}
- Report Type: {report_type.title()}

**FOCUS AREAS:** {', '.join(focus_areas).title()}

**SCAN DATA:**
{''.join(scan_details)}

{focus_instructions}

**IMPORTANT:**
- Extract REAL findings from scan outputs above
- Include SPECIFIC details (ports, versions, CVEs)
- Be concise but thorough
- Use Markdown formatting"""

            response = self.model.generate_content(prompt)

            return {
                'success': True,
                'report': response.text,
                'timestamp': datetime.now().isoformat(),
                'scan_count': len(all_scans),
                'report_type': report_type,
                'focus_areas': focus_areas
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'report': None
            }

    def _build_focus_instructions(self, report_type, focus_areas):
        """Build specific instructions based on report type and focus areas"""
        base_instruction = "**CREATE THIS REPORT STRUCTURE:**\n\n"

        if report_type == 'session':
            base_instruction += "# Current Session Security Analysis: {targets}\n\n"
        elif report_type == 'vulnerabilities':
            base_instruction += "# Vulnerability Assessment Report: {targets}\n\n"
        elif report_type == 'executive':
            base_instruction += "# Executive Security Summary: {targets}\n\n"
        elif report_type == 'technical':
            base_instruction += "# Technical Security Deep-Dive: {targets}\n\n"
        else:
            base_instruction += "# Security Assessment Report: {targets}\n\n"

        # Add sections based on focus areas
        sections = []

        if 'summary' in focus_areas or 'executive' in [report_type, 'comprehensive']:
            sections.append("""## Executive Summary
- Security posture rating (X/10) based on findings
- Count of critical/high/medium/low issues
- Top 3 concerns
- Top 3 recommendations""")

        if 'vulnerabilities' in focus_areas or report_type in ['vulnerabilities', 'comprehensive', 'session']:
            sections.append("""## Detailed Findings

### Network Security
- Specific open ports/services found
- Service versions
- Vulnerabilities

### Web Application Security
- Web server/CMS detected
- Missing security headers
- Web vulnerabilities

### System Configuration
- OS/software versions
- Outdated components
- Misconfigurations

### Information Disclosure
- Exposed data
- DNS/WHOIS concerns""")

        if 'technical' in focus_areas or report_type in ['technical', 'comprehensive']:
            sections.append("""## Technical Details
- Detailed port/service analysis
- Software version analysis
- Configuration analysis
- Potential attack vectors""")

        if 'recommendations' in focus_areas or report_type in ['comprehensive', 'session']:
            sections.append("""## Risk Matrix
| Priority | Finding | Impact | Action |
|---|---|---|---|
| Critical/High/Medium/Low | Specific issue | Why it matters | How to fix |

## Remediation Roadmap

### Phase 1: Critical (24-48hrs)
- Specific actions for critical issues

### Phase 2: High Priority (Week 1-2)
- Actions for high priority items

### Phase 3: Hardening (Month 1)
- Long-term improvements""")

        if report_type == 'comprehensive':
            sections.append("""## Compliance
- OWASP Top 10 alignment
- NIST/ISO 27001 relevance""")

        return base_instruction + '\n\n'.join(sections)

    def enhance_report_with_analytics(self, report_result, analytics_data):
        """Enhance report with analytics data if available"""
        if not report_result.get('success') or not analytics_data:
            return report_result

        try:
            # This would add analytics insights to the report
            # For now, just return the original report
            # Future enhancement could integrate chart data into the AI analysis
            return report_result
        except Exception as e:
            print(f"Warning: Failed to enhance report with analytics: {e}")
            return report_result

    def analyze_with_vulnerability_intelligence(self, scan_data):
        """Analyze scan results with integrated CVE vulnerability intelligence"""
        self._ensure_initialized()

        if not self.model:
            return {
                'error': 'AI API key not configured or network unavailable',
                'analysis': None,
                'vulnerabilities': []
            }

        try:
            scan_output = scan_data.get('output', '')

            # Get relevant CVEs from vulnerability intelligence
            relevant_cves = self.vuln_intel.find_relevant_cves(scan_output)

            # Create enhanced prompt that includes CVE information
            prompt = self._create_enhanced_analysis_prompt(scan_data, relevant_cves)

            # Get AI analysis
            response = self.model.generate_content(prompt)
            analysis = response.text

            return {
                'success': True,
                'analysis': analysis,
                'vulnerabilities': relevant_cves,
                'vulnerability_count': len(relevant_cves),
                'timestamp': datetime.now().isoformat(),
                'model': 'gemini-2.5-flash'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'analysis': None,
                'vulnerabilities': []
            }

    def _create_enhanced_analysis_prompt(self, scan_data, cves):
        """Create analysis prompt that includes CVE information"""
        base_prompt = self._create_analysis_prompt(scan_data)

        if not cves:
            return base_prompt

        # Add CVE section to the prompt
        cve_section = "\n\n**VULNERABILITY INTELLIGENCE DATA:**\n"
        cve_section += f"Found {len(cves)} potentially relevant CVEs based on detected software:\n\n"

        for i, cve in enumerate(cves[:10], 1):  # Limit to top 10 for prompt size
            cve_section += f"{i}. **{cve['id']}** ({cve.get('severity', 'UNKNOWN')} severity)\n"
            cve_section += f"   - Description: {cve.get('description', '')[:200]}...\n"
            cve_section += f"   - Detected in: {cve.get('detected_software', 'Unknown software')}\n"
            if cve.get('cvss_v3'):
                cve_section += f"   - CVSS v3 Score: {cve['cvss_v3'].get('baseScore', 'N/A')}\n"
            cve_section += "\n"

        cve_section += "\n**IMPORTANT:** Cross-reference the scan findings above with these CVEs. "
        cve_section += "Identify which vulnerabilities from the CVE database match the scan results. "
        cve_section += "Provide specific remediation steps for any confirmed vulnerabilities.\n"

        return base_prompt + cve_section

