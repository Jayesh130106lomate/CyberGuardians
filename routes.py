"""
routes.py - Flask route handlers for the security scanner application
"""
from flask import render_template, request, jsonify, Response, stream_with_context, redirect, url_for
import json
import threading
import time
from datetime import datetime
from models import SecurityScanner, current_scan, scan_history, all_scan_results
from ai_analyzer import AISecurityAnalyzer
from vulnerability_intelligence import VulnerabilityIntelligence

def register_routes(app, ai_analyzer):
    """Register all Flask routes"""
    scanner_instance = SecurityScanner()
    vuln_intel = VulnerabilityIntelligence()

    @app.route('/')
    def index():
        """Main page - Scanner tab"""
        return render_template('scanner.html', has_ai=bool(ai_analyzer))

    @app.route('/scanner')
    def scanner():
        """Scanner page - redirect to main page"""
        return redirect(url_for('index'))

    @app.route('/terminal')
    def terminal():
        """Terminal page - redirect to main page"""
        return redirect(url_for('index') + '#terminal')

    @app.route('/results')
    def results():
        """Results page - redirect to main page"""
        return redirect(url_for('index') + '#results')

    @app.route('/ai-report')
    def ai_report():
        """AI Report page - redirect to main page"""
        return redirect(url_for('index') + '#ai-report')

    @app.route('/charts')
    def charts():
        """Analytics page - redirect to main page"""
        return redirect(url_for('index') + '#charts')

    @app.route('/tools')
    def tools():
        """Tools page - redirect to main page"""
        return redirect(url_for('index') + '#tools')

    @app.route('/history')
    def history():
        """History page - redirect to main page"""
        return redirect(url_for('index') + '#history')

    @app.route('/api/check-tools')
    def check_tools():
        """API endpoint to check installed tools"""
        tools_data = scanner_instance.available_tools.copy()
        return jsonify({
            'tools': tools_data,
            'ai_enabled': bool(ai_analyzer),
            'ai_analyzer': ai_analyzer is not None
        })

    @app.route('/api/scan', methods=['POST'])
    def start_scan():
        """API endpoint to start a scan"""
        global current_scan

        if current_scan['running']:
            return jsonify({'error': 'A scan is already running'}), 400

        data = request.json
        target = data.get('target', '')
        tool = data.get('tool', 'nmap')
        intensity = data.get('intensity', 'medium')
        enable_ai = data.get('enable_ai', False)
        enable_vulnerability_intel = data.get('enable_vulnerability_intel', False)

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        if not scanner_instance.available_tools.get(tool, {}).get('installed'):
            return jsonify({'error': f'{tool} is not installed'}), 400

        def run_scan_thread():
            global current_scan
            current_scan['running'] = True
            current_scan['stop_requested'] = False  # Reset stop flag
            current_scan['current_process'] = None
            current_scan['output_buffer'] = []  # Clear output buffer
            current_scan['accumulated_output'] = ''  # ✅ Reset accumulated output for live AI
            current_scan['live_ai_analysis'] = ''  # ✅ Reset live AI analysis
            current_scan['progress'] = 10
            current_scan['tool'] = tool
            current_scan['target'] = target
            current_scan['intensity'] = intensity  # ✅ Store intensity
            current_scan['terminal_output'] = app.config['scan_queue']
            # ✅ Clear chain results to prevent confusion with single scan results
            current_scan['chain_results'] = []

            result = None

            # Run the scan based on tool
            if tool == 'nmap':
                result = scanner_instance.run_nmap_scan(target, intensity, current_scan['terminal_output'])
            elif tool == 'wpscan':
                result = scanner_instance.run_wpscan(target, intensity, current_scan['terminal_output'])
            elif tool == 'nikto':
                result = scanner_instance.run_nikto_scan(target, intensity, current_scan['terminal_output'])
            elif tool == 'whatweb':
                result = scanner_instance.run_whatweb_scan(target, intensity, current_scan['terminal_output'])
            elif tool == 'whois':
                result = scanner_instance.info_tools.whois_lookup(target)
                if result:
                    current_scan['terminal_output'].put(result.get('output', ''))
            elif tool == 'dnslookup':
                result = scanner_instance.info_tools.dns_lookup(target, intensity)
                if result:
                    current_scan['terminal_output'].put(result.get('output', ''))
            elif tool == 'sslcheck':
                result = scanner_instance.info_tools.ssl_check(target)
                if result:
                    current_scan['terminal_output'].put(result.get('output', ''))
            elif tool == 'httpheaders':
                result = scanner_instance.info_tools.http_headers(target)
                if result:
                    current_scan['terminal_output'].put(result.get('output', ''))
            elif tool == 'portscan':
                result = scanner_instance.info_tools.port_scan_quick(target)
                if result:
                    current_scan['terminal_output'].put(result.get('output', ''))

            current_scan['progress'] = 80

            # AI Analysis if enabled
            ai_analysis = None
            if enable_ai and ai_analyzer:
                current_scan['progress'] = 85
                current_scan['terminal_output'].put("\n\n🤖 AI Analysis in progress...\n")

                scan_data = {
                    'tool': tool,
                    'target': target,
                    'intensity': intensity,
                    'timestamp': datetime.now().isoformat(),
                    'output': result.get('output', '') + result.get('error', '')
                }

                # Use vulnerability intelligence if enabled
                if enable_vulnerability_intel:
                    ai_analysis = ai_analyzer.analyze_with_vulnerability_intelligence(scan_data)
                    current_scan['terminal_output'].put("\n✓ AI Analysis with Vulnerability Intelligence Complete\n")
                else:
                    ai_analysis = ai_analyzer.analyze_scan_results(scan_data)
                    current_scan['terminal_output'].put("\n✓ AI Analysis Complete\n")

            current_scan['progress'] = 100
            current_scan['results'] = result
            current_scan['ai_analysis'] = ai_analysis
            current_scan['timestamp'] = datetime.now().isoformat()

            # Add to history and all results
            scan_record = {
                'tool': tool,
                'target': target,
                'intensity': intensity,
                'timestamp': current_scan['timestamp'],
                'success': result['success'] if result else False,
                'has_ai': bool(ai_analysis)
            }
            scan_history.append(scan_record)

            if result:
                all_scan_results.append({
                    **scan_record,
                    'output': result.get('output', ''),
                    'ai_analysis': ai_analysis
                })

            current_scan['running'] = False

        thread = threading.Thread(target=run_scan_thread)
        thread.daemon = True
        thread.start()

        return jsonify({'message': 'Scan started', 'scan_id': len(scan_history)})

    @app.route('/api/scan-status')
    def scan_status():
        """API endpoint to check scan status"""
        status = {
            'running': current_scan['running'],
            'progress': current_scan['progress'],
            'tool': current_scan.get('tool', ''),
            'target': current_scan.get('target', ''),
            'results': current_scan.get('results'),
            'ai_analysis': current_scan.get('ai_analysis'),
            'chain_results': current_scan.get('chain_results', []),
            'ai_report': current_scan.get('ai_report'),
            'timestamp': current_scan.get('timestamp'),
            'live_ai_analysis': current_scan.get('live_ai_analysis', ''),  # ✅ Include live AI analysis
            'accumulated_output': current_scan.get('accumulated_output', '')  # ✅ Include accumulated output
        }
        return jsonify(status)

    @app.route('/api/stop-scan', methods=['POST'])
    def stop_scan():
        """API endpoint to stop the running scan"""
        global current_scan

        if not current_scan['running']:
            return jsonify({'error': 'No scan is running'}), 400

        # Set stop flag
        current_scan['stop_requested'] = True

        # Kill the process if it exists
        if current_scan.get('current_process'):
            try:
                current_scan['current_process'].kill()
                current_scan['current_process'] = None
            except Exception as e:
                print(f"Error killing process: {e}")

        # Clear running status
        current_scan['running'] = False
        current_scan['stop_requested'] = False
        current_scan['terminal_output'].put("\n🛑 Scan stopped by user\n")

        return jsonify({'message': 'Scan stopped successfully'})

    @app.route('/api/terminal-stream')
    def terminal_stream():
        """Stream terminal output in real-time"""
        def generate():
            # print("🔌 Terminal stream started")  # Debug log - commented out
            while True:
                # Check if terminal_output exists and is not None
                terminal_output = current_scan.get('terminal_output')
                if terminal_output and not terminal_output.empty():
                    line = terminal_output.get()

                    # Skip None or empty lines
                    if not line or line.strip() == '':
                        continue

                    # print(f"📤 Streaming line: {line[:50]}...")  # Debug log - commented out

                    # Detect severity based on keywords
                    line_lower = line.lower() if isinstance(line, str) else ''
                    severity = 'info'
                    if any(word in line_lower for word in ['critical', 'exploit', 'rce', 'sql injection']):
                        severity = 'critical'
                    elif any(word in line_lower for word in ['high', 'dangerous', 'severe', 'vulnerability']):
                        severity = 'high'
                    elif any(word in line_lower for word in ['medium', 'warning', 'potential']):
                        severity = 'medium'
                    elif any(word in line_lower for word in ['low', 'minor', 'info']):
                        severity = 'low'
                    elif any(word in line_lower for word in ['error', 'failed', 'timeout']):
                        severity = 'error'
                    elif any(word in line_lower for word in ['success', 'completed', 'done']):
                        severity = 'success'

                    yield f"data: {json.dumps({'output': line, 'type': severity})}\n\n"
                else:
                    if not current_scan.get('running', False):
                        # print("✅ Scan finished, closing stream")  # Debug log - commented out
                        yield f"data: {json.dumps({'done': True})}\n\n"
                        break
                    time.sleep(0.1)

        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    @app.route('/api/live-ai-analysis', methods=['POST'])
    def live_ai_analysis():
        """Generate live AI analysis from accumulated terminal output"""
        if not ai_analyzer:
            return jsonify({'status': 'error', 'message': 'AI not configured'}), 400

        if not current_scan['running']:
            return jsonify({'status': 'error', 'message': 'No scan is running'}), 400

        # Get accumulated output
        accumulated_output = current_scan.get('accumulated_output', '')

        if not accumulated_output or len(accumulated_output.strip()) < 50:
            return jsonify({
                'status': 'waiting',
                'message': 'Not enough data yet for analysis',
                'analysis': ''
            })

        try:
            # Prepare scan data for AI analysis
            scan_data = {
                'tool': current_scan.get('tool', 'unknown'),
                'target': current_scan.get('target', 'unknown'),
                'output': accumulated_output,
                'timestamp': datetime.now().isoformat(),
                'intensity': current_scan.get('intensity', 'medium'),
                'partial': True  # Indicate this is partial/live analysis
            }

            print(f"🤖 Generating live AI analysis ({len(accumulated_output)} chars)...")

            # Generate AI analysis
            ai_result = ai_analyzer.analyze_scan_results(scan_data)

            if ai_result and ai_result.get('success'):
                analysis_text = ai_result.get('analysis', '')
                # Store in current_scan for polling
                current_scan['live_ai_analysis'] = analysis_text

                return jsonify({
                    'status': 'success',
                    'analysis': analysis_text,
                    'output_length': len(accumulated_output)
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'AI analysis failed',
                    'error': ai_result.get('error', 'Unknown error')
                })

        except Exception as e:
            print(f"❌ Live AI analysis error: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/scan-history')
    def get_scan_history():
        """API endpoint to get scan history"""
        return jsonify(scan_history)

    @app.route('/api/clear-history', methods=['POST'])
    def clear_history():
        """API endpoint to clear scan history"""
        global scan_history, all_scan_results
        scan_history = []
        all_scan_results = []
        return jsonify({'message': 'History cleared'})

    @app.route('/api/ai-report', methods=['POST'])
    def generate_ai_report():
        """Generate comprehensive AI report from scan data"""
        if not ai_analyzer:
            return jsonify({'status': 'error', 'message': 'AI not configured. Please set GEMINI_API_KEY'}), 400

        data = request.json or {}

        # Check if using new enhanced format or legacy format
        if 'scan_data' in data:
            # New enhanced format
            scan_data = data.get('scan_data', [])
            report_type = data.get('report_type', 'comprehensive')
            focus_areas = data.get('focus_areas', [])
            include_analytics = data.get('include_analytics', False)
            analytics_data = data.get('analytics_data', {})
            session_only = data.get('session_only', False)

            print(f"🤖 Enhanced AI Report: type={report_type}, focus_areas={focus_areas}, session_only={session_only}")
            print(f"📊 Scan data: {len(scan_data)} scans")

        else:
            # Legacy format - convert to new format
            frontend_history = data.get('history', [])
            include_history = data.get('include_history', True)
            include_charts = data.get('include_charts', True)

            print(f"� Legacy AI Report: include_history={include_history}, include_charts={include_charts}")

            # Convert legacy format to new format
            scan_data = []
            report_type = 'comprehensive'
            focus_areas = ['vulnerabilities', 'recommendations', 'summary']
            include_analytics = include_charts
            analytics_data = {}
            session_only = False

            if frontend_history and len(frontend_history) > 0:
                # Convert frontend history to scan data format
                for idx, scan in enumerate(frontend_history):
                    output_data = scan.get('output', '')

                    # If no output field, try to get it from results
                    if not output_data and 'results' in scan:
                        output_data = scan.get('results', {}).get('output', '')

                    # Build scan entry
                    scan_entry = {
                        'tool': scan.get('tool', scan.get('type', 'unknown')),
                        'target': scan.get('target', 'unknown'),
                        'output': output_data if output_data else f"No output captured for {scan.get('tool', 'scan')}",
                        'timestamp': scan.get('timestamp', ''),
                        'success': scan.get('status') == 'success',
                        'intensity': scan.get('intensity', 'medium')
                    }
                    scan_data.append(scan_entry)
            elif all_scan_results and include_history:
                scan_data = all_scan_results

        # Validate we have scan data
        if not scan_data:
            return jsonify({'status': 'error', 'message': 'No scan results available. Please run a scan first.'}), 400

        # Filter out scans without meaningful output
        meaningful_scans = [s for s in scan_data if s.get('output') and len(s.get('output', '')) > 20]

        if not meaningful_scans:
            return jsonify({'status': 'error', 'message': 'No scan results with output data. Please run scans first.'}), 400

        print(f"🤖 Generating {report_type} AI report from {len(meaningful_scans)} scans...")

        try:
            # Generate report based on type and focus areas
            if report_type == 'session' or session_only:
                # Session-specific analysis
                result = ai_analyzer.generate_session_report(meaningful_scans, focus_areas)
            elif report_type == 'vulnerabilities':
                result = ai_analyzer.generate_vulnerability_report(meaningful_scans, focus_areas)
            elif report_type == 'executive':
                result = ai_analyzer.generate_executive_summary(meaningful_scans, focus_areas)
            elif report_type == 'technical':
                result = ai_analyzer.generate_technical_report(meaningful_scans, focus_areas)
            else:
                # Comprehensive report
                result = ai_analyzer.generate_comprehensive_report(meaningful_scans, focus_areas)

            # Include analytics data if requested
            if include_analytics and analytics_data:
                result = ai_analyzer.enhance_report_with_analytics(result, analytics_data)

            # Check if AI analyzer returned an error
            if not result.get('success', False):
                error_msg = result.get('error', 'Unknown error during report generation')
                print(f"❌ AI report error: {error_msg}")
                return jsonify({'status': 'error', 'message': error_msg}), 500

            # Extract the actual report text from the result
            report_text = result.get('report', '')

            if not report_text:
                return jsonify({'status': 'error', 'message': 'Report generation returned empty result'}), 500

            print(f"✅ AI report generated successfully ({len(report_text)} characters)")
            print(f"📝 Report preview (first 200 chars): {report_text[:200]}...")

            # Return the report with metadata
            return jsonify({
                'status': 'success',
                'report': report_text,
                'report_type': report_type,
                'focus_areas': focus_areas,
                'scan_count': len(meaningful_scans)
            })

        except Exception as e:
            print(f"❌ AI report exception: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/chain-scan', methods=['POST'])
    def start_chain_scan():
        """Start a chain of scans"""
        global current_scan

        if current_scan['running']:
            return jsonify({'error': 'A scan is already running'}), 400

        data = request.json
        target = data.get('target', '')
        tools = data.get('tools', [])
        intensity = data.get('intensity', 'medium')
        enable_ai = data.get('enable_ai', False)
        enable_vulnerability_intel = data.get('enable_vulnerability_intel', False)

        if not target or not tools:
            return jsonify({'error': 'Target and tools are required'}), 400

        def run_chain_thread():
            global current_scan
            current_scan['running'] = True
            current_scan['chain_results'] = []
            current_scan['output_buffer'] = []  # Clear output buffer
            current_scan['accumulated_output'] = ''  # ✅ Reset accumulated output for live AI
            current_scan['live_ai_analysis'] = ''  # ✅ Reset live AI analysis
            current_scan['terminal_output'] = app.config['scan_queue']
            current_scan['stop_requested'] = False  # Reset stop flag
            current_scan['current_process'] = None
            current_scan['intensity'] = intensity  # ✅ Store intensity
            current_scan['target'] = target  # ✅ Store target
            # ✅ Clear single scan results to prevent confusion with chain scan results
            current_scan['results'] = None
            current_scan['ai_analysis'] = None

            total_tools = len(tools)

            for idx, tool in enumerate(tools):
                current_scan['progress'] = int((idx / total_tools) * 90)
                current_scan['tool'] = tool
                current_scan['target'] = target
                current_scan['output_buffer'] = []  # Clear buffer for each tool

                current_scan['terminal_output'].put(f"\n{'='*50}\n")
                current_scan['terminal_output'].put(f"Running {tool} scan ({idx+1}/{total_tools})...\n")
                current_scan['terminal_output'].put(f"{'='*50}\n\n")

                # Run individual scan
                result = None
                if tool == 'nmap':
                    result = scanner_instance.run_nmap_scan(target, intensity, current_scan['terminal_output'])
                elif tool == 'wpscan':
                    result = scanner_instance.run_wpscan(target, intensity, current_scan['terminal_output'])
                elif tool == 'nikto':
                    result = scanner_instance.run_nikto_scan(target, intensity, current_scan['terminal_output'])
                elif tool == 'whatweb':
                    result = scanner_instance.run_whatweb_scan(target, intensity, current_scan['terminal_output'])
                elif tool == 'whois':
                    result = scanner_instance.info_tools.whois_lookup(target)
                    if result:
                        current_scan['terminal_output'].put(result.get('output', ''))
                elif tool == 'dnslookup':
                    result = scanner_instance.info_tools.dns_lookup(target, intensity)
                    if result:
                        current_scan['terminal_output'].put(result.get('output', ''))
                elif tool == 'sslcheck':
                    result = scanner_instance.info_tools.ssl_check(target)
                    if result:
                        current_scan['terminal_output'].put(result.get('output', ''))
                elif tool == 'httpheaders':
                    result = scanner_instance.info_tools.http_headers(target)
                    if result:
                        current_scan['terminal_output'].put(result.get('output', ''))
                elif tool == 'portscan':
                    result = scanner_instance.info_tools.port_scan_quick(target)
                    if result:
                        current_scan['terminal_output'].put(result.get('output', ''))

                if result:
                    current_scan['chain_results'].append({
                        'tool': tool,
                        'result': result
                    })

                    all_scan_results.append({
                        'tool': tool,
                        'target': target,
                        'intensity': intensity,
                        'timestamp': datetime.now().isoformat(),
                        'success': result.get('success', False),
                        'output': result.get('output', '')
                    })

            # Generate AI report if enabled
            if enable_ai and ai_analyzer:
                current_scan['progress'] = 95
                current_scan['terminal_output'].put("\n\n🤖 Generating comprehensive AI report...\n")

                # Filter to only include scans with output
                scans_with_data = [s for s in all_scan_results if s.get('output')]

                print(f"🔍 DEBUG Chain Scan: Total scans={len(all_scan_results)}, With output={len(scans_with_data)}")

                if scans_with_data:
                    try:
                        # Use vulnerability intelligence if enabled
                        if enable_vulnerability_intel:
                            # Combine all scan outputs for vulnerability analysis
                            combined_output = '\n\n'.join([s.get('output', '') for s in scans_with_data])
                            vuln_scan_data = {
                                'tool': 'chain-scan',
                                'target': target,
                                'output': combined_output,
                                'timestamp': datetime.now().isoformat()
                            }
                            report = ai_analyzer.analyze_with_vulnerability_intelligence(vuln_scan_data)
                        else:
                            report = ai_analyzer.generate_comprehensive_report(scans_with_data)

                        if report.get('success'):
                            current_scan['ai_report'] = report.get('report', '')
                            current_scan['terminal_output'].put("\n✓ AI Report Generated Successfully\n")
                            print(f"✅ AI Report generated: {len(report.get('report', ''))} characters")
                        else:
                            error_msg = report.get('error', 'Unknown error')
                            current_scan['terminal_output'].put(f"\n❌ AI Report failed: {error_msg}\n")
                            print(f"❌ AI Report error: {error_msg}")
                    except Exception as e:
                        error_msg = f"AI report exception: {str(e)}"
                        current_scan['terminal_output'].put(f"\n❌ {error_msg}\n")
                        print(f"❌ {error_msg}")
                else:
                    current_scan['terminal_output'].put("\n⚠️ No scan data available for AI report\n")
                    print("⚠️ Chain scan: No scans with output data for AI report")

            current_scan['progress'] = 100
            current_scan['timestamp'] = datetime.now().isoformat()
            current_scan['running'] = False

            # Add to history
            scan_history.append({
                'type': 'chain',
                'tools': tools,
                'target': target,
                'intensity': intensity,
                'timestamp': current_scan['timestamp'],
                'success': True,
                'has_ai': enable_ai
            })

        thread = threading.Thread(target=run_chain_thread)
        thread.daemon = True
        thread.start()

        return jsonify({'message': 'Chain scan started', 'tools': tools})

    @app.route('/api/cve/search', methods=['GET'])
    def search_cves():
        """Search for CVEs by keyword"""
        keyword = request.args.get('keyword', '').strip()
        limit = min(int(request.args.get('limit', 20)), 50)  # Max 50 results

        if not keyword:
            return jsonify({'error': 'Keyword parameter is required'}), 400

        try:
            cves = vuln_intel.search_cves_by_keyword(keyword, limit)
            return jsonify({
                'success': True,
                'keyword': keyword,
                'count': len(cves),
                'vulnerabilities': cves
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/cve/details/<cve_id>')
    def get_cve_details(cve_id):
        """Get detailed information for a specific CVE"""
        try:
            cve_details = vuln_intel.get_cve_details(cve_id)
            if cve_details:
                return jsonify({
                    'success': True,
                    'vulnerability': cve_details
                })
            else:
                return jsonify({'error': 'CVE not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scan/vulnerability-analysis', methods=['POST'])
    def vulnerability_analysis():
        """Perform vulnerability analysis with CVE intelligence"""
        if not ai_analyzer:
            return jsonify({'error': 'AI not configured'}), 400

        data = request.json or {}
        scan_output = data.get('scan_output', '')
        tool = data.get('tool', 'unknown')
        target = data.get('target', 'unknown')

        if not scan_output:
            return jsonify({'error': 'Scan output is required'}), 400

        try:
            scan_data = {
                'tool': tool,
                'target': target,
                'output': scan_output,
                'timestamp': datetime.now().isoformat()
            }

            # Use the enhanced analysis with vulnerability intelligence
            result = ai_analyzer.analyze_with_vulnerability_intelligence(scan_data)

            if result.get('success'):
                return jsonify({
                    'success': True,
                    'analysis': result.get('analysis'),
                    'vulnerabilities': result.get('vulnerabilities', []),
                    'vulnerability_count': result.get('vulnerability_count', 0)
                })
            else:
                return jsonify({'error': result.get('error', 'Analysis failed')}), 500

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/set-api-key', methods=['POST'])
    def set_api_key():
        """Set Gemini API key"""
        global ai_analyzer

        data = request.json
        api_key = data.get('api_key', '')

        if not api_key:
            return jsonify({'error': 'API key is required'}), 400

        # Update the global ai_analyzer
        from ai_analyzer import AISecurityAnalyzer
        ai_analyzer = AISecurityAnalyzer(api_key)

        return jsonify({'message': 'API key set successfully', 'has_ai': True})