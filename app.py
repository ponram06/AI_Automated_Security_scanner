from flask import Flask, request, jsonify, render_template
import os
from datetime import datetime
import traceback

# Import your scanner modules
from utils.xss_scanner import XSSScanner
from utils.sqli_scanner import SQLInjectionScanner
from utils.crawler import WebCrawler
from utils.ai_analysis import AIAnalyzer
from utils.report_generator import ReportGenerator
from config import GEMINI_API_KEY

# Initialize Flask app
app = Flask(__name__)

# Initialize scanners
try:
    xss_scanner = XSSScanner()
    print("[+] XSS Scanner initialized")
except Exception as e:
    print(f"[!] Failed to initialize XSS Scanner: {e}")
    xss_scanner = None

try:
    sqli_scanner = SQLInjectionScanner()
    print("[+] SQL Injection Scanner initialized")
except Exception as e:
    print(f"[!] Failed to initialize SQL Injection Scanner: {e}")
    sqli_scanner = None

try:
    web_crawler = WebCrawler()
    print("[+] Web Crawler initialized")
except Exception as e:
    print(f"[!] Failed to initialize Web Crawler: {e}")
    web_crawler = None

try:
    ai_analyzer = AIAnalyzer(GEMINI_API_KEY) if GEMINI_API_KEY else None
    if ai_analyzer:
        print("[+] AI Analyzer initialized")
    else:
        print("[!] AI Analyzer not initialized - no API key")
except Exception as e:
    print(f"[!] Failed to initialize AI Analyzer: {e}")
    ai_analyzer = None

# Initialize report generator
try:
    report_generator = ReportGenerator()
    print("[+] Report Generator initialized")
except Exception as e:
    print(f"[!] Failed to initialize Report Generator: {e}")
    report_generator = None

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Main scanning endpoint"""
    try:
        data = request.get_json()
        target_url = data.get('url')
        crawl_enabled = data.get('crawl_enabled', True)
        scan_types = data.get('scan_types', ['xss', 'sqli'])
        generate_report_flag = data.get('generate_report', False)
        
        if not target_url:
            return jsonify({'error': 'No target URL provided'}), 400
        
        print(f"🎯 Starting scan on: {target_url}")
        print(f"🔍 Scan types: {scan_types}")
        print(f"🕷️ Crawling enabled: {crawl_enabled}")
        
        # Initialize results structure
        scan_results = {
            'target_url': target_url,
            'timestamp': datetime.now().isoformat(),
            'scan_types': scan_types,
            'crawl_enabled': crawl_enabled,
            'results': []
        }
        
        # Get URLs to scan
        urls_to_scan = [target_url]
        
        if crawl_enabled and web_crawler:
            try:
                print(f"🕷️ Starting crawl on: {target_url}")
                crawled_urls = web_crawler.crawl_site(target_url, max_depth=2)
                urls_to_scan = list(set(crawled_urls))  # Remove duplicates
                print(f"🕷️ Found {len(urls_to_scan)} URLs to scan")
            except Exception as e:
                print(f"⚠️ Crawling failed: {e}")
                # Continue with just the target URL
        
        # Scan each URL
        for url in urls_to_scan:
            print(f"🔍 Scanning: {url}")
            
            url_result = {
                'url': url,
                'xss_results': {'vulnerable': False, 'vulnerabilities': []},
                'sqli_results': {'vulnerable': False, 'vulnerabilities': []}
            }
            
            # XSS Scanning
            if 'xss' in scan_types and xss_scanner:
                try:
                    print(f"🔍 Running XSS scan on: {url}")
                    xss_result = xss_scanner.scan_url(url)
                    url_result['xss_results'] = xss_result
                    
                    if xss_result.get('vulnerable'):
                        print(f"⚠️ XSS vulnerability found in: {url}")
                        
                except Exception as e:
                    print(f"❌ XSS scan error for {url}: {e}")
                    url_result['xss_results']['error'] = str(e)
            
            # SQL Injection Scanning
            if 'sqli' in scan_types and sqli_scanner:
                try:
                    print(f"🔍 Running SQL injection scan on: {url}")
                    sqli_result = sqli_scanner.scan_url(url)
                    url_result['sqli_results'] = sqli_result
                    
                    if sqli_result.get('vulnerable'):
                        print(f"⚠️ SQL injection vulnerability found in: {url}")
                        
                except Exception as e:
                    print(f"❌ SQL injection scan error for {url}: {e}")
                    url_result['sqli_results']['error'] = str(e)
            
            scan_results['results'].append(url_result)
        
        # AI Analysis
        if ai_analyzer:
            try:
                print("🤖 Running AI analysis...")
                ai_analysis = ai_analyzer.analyze_vulnerabilities(scan_results)
                scan_results['ai_analysis'] = ai_analysis
            except Exception as e:
                print(f"❌ AI analysis failed: {e}")
                scan_results['ai_analysis'] = {
                    'error': str(e),
                    'ai_powered': False
                }
        
        # Calculate summary statistics
        total_vulnerabilities = 0
        vulnerable_urls = 0
        
        for result in scan_results['results']:
            url_has_vulns = False
            
            if result['xss_results'].get('vulnerable'):
                total_vulnerabilities += len(result['xss_results'].get('vulnerabilities', []))
                url_has_vulns = True
            
            if result['sqli_results'].get('vulnerable'):
                total_vulnerabilities += len(result['sqli_results'].get('vulnerabilities', []))
                url_has_vulns = True
            
            if url_has_vulns:
                vulnerable_urls += 1
        
        scan_results['summary'] = {
            'total_urls_scanned': len(urls_to_scan),
            'vulnerable_urls': vulnerable_urls,
            'total_vulnerabilities': total_vulnerabilities,
            'scan_duration': 'completed',
            'status': 'completed'
        }
        
        # Auto-generate report if requested
        if generate_report_flag and report_generator:
            report_path = auto_generate_report(scan_results)
            if report_path:
                scan_results['report_generated'] = True
                scan_results['report_path'] = report_path
                print(f"✅ Report generated: {report_path}")
            else:
                scan_results['report_generated'] = False
                print("❌ Report generation failed")
        
        print(f"✅ Scan completed. Found {total_vulnerabilities} vulnerabilities across {vulnerable_urls} URLs")
        
        return jsonify(scan_results)
        
    except Exception as e:
        print(f"❌ Scan error: {e}")
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'status': 'error',
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Generate PDF report"""
    try:
        data = request.get_json()
        
        if not report_generator:
            return jsonify({'error': 'Report generator not available'}), 500
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(os.getcwd(), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{timestamp}.pdf"
        filepath = os.path.join(reports_dir, filename)
        
        print(f"[+] Generating report at: {filepath}")
        
        # Generate the PDF report
        success = report_generator.generate_pdf_report(data, filepath)
        
        # Verify file was created
        if success and os.path.exists(filepath):
            print(f"[+] Report successfully generated: {filepath}")
            return jsonify({
                'success': True,
                'message': 'Report generated successfully',
                'filename': filename,
                'filepath': filepath
            })
        else:
            return jsonify({'error': 'Report file was not created'}), 500
        
    except Exception as e:
        print(f"[!] Report generation error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

def auto_generate_report(scan_results):
    """Automatically generate report after scan completion"""
    try:
        if not report_generator:
            print("[!] Report generator not available")
            return None
            
        reports_dir = os.path.join(os.getcwd(), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{timestamp}.pdf"
        filepath = os.path.join(reports_dir, filename)
        
        print(f"[+] Auto-generating report: {filepath}")
        success = report_generator.generate_pdf_report(scan_results, filepath)
        
        return filepath if success and os.path.exists(filepath) else None
        
    except Exception as e:
        print(f"[!] Auto report generation failed: {e}")
        return None

if __name__ == '__main__':
    print("🚀 Starting AI Cybersecurity Scanner...")
    print("🌐 Server will be available at: http://localhost:5000")
    
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('utils', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)