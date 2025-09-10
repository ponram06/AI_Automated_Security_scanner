import google.generativeai as genai
from typing import Dict, List, Any
import json
import os

class AIAnalyzer:
    def __init__(self, api_key: str = None):
        """Initialize AI analyzer with Gemini API"""
        if api_key:
            self.api_key = api_key
        else:
            # Try to get from environment variable
            self.api_key = os.getenv('GEMINI_API_KEY')
        
        if self.api_key:
            genai.configure(api_key=self.api_key)
            try:
                self.model = genai.GenerativeModel('gemini-pro')
                self.ai_available = True
                print("[+] AI analyzer initialized with Gemini Pro")
            except Exception as e:
                print(f"[!] Error initializing Gemini: {str(e)}")
                self.ai_available = False
        else:
            print("[!] No Gemini API key provided - AI analysis disabled")
            self.ai_available = False
    
    def analyze_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results using AI"""
        if not self.ai_available:
            return self._fallback_analysis(scan_results)
        
        try:
            # Prepare data for AI analysis
            analysis_prompt = self._create_analysis_prompt(scan_results)
            
            # Generate AI analysis
            response = self.model.generate_content(analysis_prompt)
            
            # Parse AI response
            ai_analysis = self._parse_ai_response(response.text)
            
            # Add metadata
            ai_analysis.update({
                'ai_powered': True,
                'analysis_timestamp': scan_results.get('timestamp', ''),
                'total_urls_scanned': len(scan_results.get('results', []))
            })
            
            return ai_analysis
            
        except Exception as e:
            print(f"[!] Error in AI analysis: {str(e)}")
            return self._fallback_analysis(scan_results)
    
    def _create_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """Create a comprehensive prompt for AI analysis"""
        
        # Extract vulnerability summary
        total_vulns = 0
        xss_vulns = 0
        sqli_vulns = 0
        high_severity = 0
        
        vulnerable_urls = []
        
        for result in scan_results.get('results', []):
            if result.get('xss_results', {}).get('vulnerable'):
                xss_vulns += len(result['xss_results'].get('vulnerabilities', []))
                vulnerable_urls.append(result['url'])
            
            if result.get('sqli_results', {}).get('vulnerable'):
                sqli_vulns += len(result['sqli_results'].get('vulnerabilities', []))
                if result['url'] not in vulnerable_urls:
                    vulnerable_urls.append(result['url'])
        
        total_vulns = xss_vulns + sqli_vulns
        
        prompt = f"""
You are a cybersecurity expert analyzing web application security scan results. Provide a comprehensive analysis in JSON format.

SCAN SUMMARY:
- Total URLs scanned: {len(scan_results.get('results', []))}
- Total vulnerabilities found: {total_vulns}
- XSS vulnerabilities: {xss_vulns}
- SQL Injection vulnerabilities: {sqli_vulns}
- Vulnerable URLs: {len(vulnerable_urls)}

DETAILED RESULTS:
{json.dumps(scan_results, indent=2)}

Please provide analysis in the following JSON structure:
{{
    "executive_summary": "Brief overview of security posture",
    "risk_level": "Critical|High|Medium|Low",
    "priority_vulnerabilities": [
        {{
            "type": "vulnerability_type",
            "severity": "High|Medium|Low",
            "count": number_of_instances,
            "description": "detailed_description",
            "impact": "potential_impact"
        }}
    ],
    "recommendations": [
        {{
            "priority": "High|Medium|Low",
            "action": "recommended_action",
            "rationale": "why_this_is_important"
        }}
    ],
    "technical_details": {{
        "most_common_vulnerability": "type",
        "attack_vectors": ["vector1", "vector2"],
        "affected_parameters": ["param1", "param2"]
    }},
    "remediation_steps": [
        {{
            "step": "specific_action",
            "difficulty": "Easy|Medium|Hard",
            "estimated_time": "time_estimate"
        }}
    ]
}}

Focus on actionable insights and prioritize based on actual risk to the application.
"""
        return prompt
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI response and extract JSON analysis"""
        try:
            # Try to extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
            else:
                # Fallback: create structured response from text
                return {
                    "executive_summary": response_text[:200] + "..." if len(response_text) > 200 else response_text,
                    "risk_level": "Medium",
                    "ai_analysis_text": response_text
                }
                
        except json.JSONDecodeError:
            # If JSON parsing fails, return text analysis
            return {
                "executive_summary": "AI analysis completed but JSON parsing failed",
                "risk_level": "Medium", 
                "ai_analysis_text": response_text
            }
    
    def _fallback_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Provide basic analysis when AI is not available"""
        total_vulns = 0
        xss_count = 0
        sqli_count = 0
        high_severity_count = 0
        vulnerable_urls = []
        
        # Count vulnerabilities
        for result in scan_results.get('results', []):
            if result.get('xss_results', {}).get('vulnerable'):
                xss_vulns = result['xss_results'].get('vulnerabilities', [])
                xss_count += len(xss_vulns)
                vulnerable_urls.append(result['url'])
                
                # Count high severity
                for vuln in xss_vulns:
                    if vuln.get('severity') == 'High':
                        high_severity_count += 1
            
            if result.get('sqli_results', {}).get('vulnerable'):
                sqli_vulns = result['sqli_results'].get('vulnerabilities', [])
                sqli_count += len(sqli_vulns)
                if result['url'] not in vulnerable_urls:
                    vulnerable_urls.append(result['url'])
                
                # Count high severity
                for vuln in sqli_vulns:
                    if vuln.get('severity') == 'High':
                        high_severity_count += 1
        
        total_vulns = xss_count + sqli_count
        
        # Determine risk level
        if high_severity_count > 0:
            risk_level = "High"
        elif total_vulns > 3:
            risk_level = "Medium"
        elif total_vulns > 0:
            risk_level = "Low"
        else:
            risk_level = "Low"
        
        # Generate executive summary
        if total_vulns == 0:
            summary = "No critical vulnerabilities detected. The scanned applications appear to have basic security measures in place."
        else:
            summary = f"Security scan identified {total_vulns} vulnerabilities across {len(vulnerable_urls)} URLs. "
            if xss_count > 0:
                summary += f"Found {xss_count} XSS vulnerabilities. "
            if sqli_count > 0:
                summary += f"Found {sqli_count} SQL injection vulnerabilities. "
            summary += "Immediate remediation recommended."
        
        # Generate recommendations
        recommendations = []
        if xss_count > 0:
            recommendations.append({
                "priority": "High",
                "action": "Implement input validation and output encoding to prevent XSS attacks",
                "rationale": "XSS vulnerabilities can lead to session hijacking and data theft"
            })
        
        if sqli_count > 0:
            recommendations.append({
                "priority": "High", 
                "action": "Use parameterized queries and input validation to prevent SQL injection",
                "rationale": "SQL injection can lead to complete database compromise"
            })
        
        if total_vulns == 0:
            recommendations.append({
                "priority": "Medium",
                "action": "Continue regular security assessments and implement additional security headers",
                "rationale": "Proactive security measures help prevent future vulnerabilities"
            })
        
        return {
            "ai_powered": False,
            "executive_summary": summary,
            "risk_level": risk_level,
            "total_vulnerabilities": total_vulns,
            "vulnerability_breakdown": {
                "xss": xss_count,
                "sqli": sqli_count,
                "high_severity": high_severity_count
            },
            "vulnerable_urls": vulnerable_urls,
            "recommendations": recommendations,
            "technical_details": {
                "most_common_vulnerability": "XSS" if xss_count >= sqli_count else "SQL Injection" if sqli_count > 0 else "None",
                "total_urls_scanned": len(scan_results.get('results', [])),
                "vulnerable_url_count": len(vulnerable_urls)
            }
        }
    
    def generate_remediation_guide(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed remediation guide for found vulnerabilities"""
        if not self.ai_available:
            return self._fallback_remediation_guide(vulnerabilities)
        
        try:
            remediation_prompt = f"""
As a cybersecurity expert, provide a detailed remediation guide for the following vulnerabilities:

{json.dumps(vulnerabilities, indent=2)}

Provide response in JSON format with:
{{
    "immediate_actions": ["action1", "action2"],
    "long_term_solutions": ["solution1", "solution2"],
    "code_examples": {{
        "xss_prevention": "code_example",
        "sqli_prevention": "code_example"
    }},
    "testing_recommendations": ["test1", "test2"],
    "monitoring_suggestions": ["monitor1", "monitor2"]
}}
"""
            
            response = self.model.generate_content(remediation_prompt)
            return self._parse_ai_response(response.text)
            
        except Exception as e:
            print(f"[!] Error generating remediation guide: {str(e)}")
            return self._fallback_remediation_guide(vulnerabilities)
    
    def _fallback_remediation_guide(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Fallback remediation guide when AI is unavailable"""
        has_xss = any(v.get('type', '').lower().find('xss') != -1 for v in vulnerabilities)
        has_sqli = any(v.get('type', '').lower().find('sql') != -1 for v in vulnerabilities)
        
        immediate_actions = []
        long_term_solutions = []
        code_examples = {}
        
        if has_xss:
            immediate_actions.append("Review and sanitize all user inputs")
            immediate_actions.append("Implement Content Security Policy (CSP)")
            long_term_solutions.append("Implement comprehensive input validation framework")
            code_examples["xss_prevention"] = "Use htmlspecialchars() in PHP or equivalent encoding functions"
        
        if has_sqli:
            immediate_actions.append("Review database queries and implement parameterized statements")
            immediate_actions.append("Apply principle of least privilege to database accounts")
            long_term_solutions.append("Implement ORM/query builder to prevent direct SQL construction")
            code_examples["sqli_prevention"] = "Use prepared statements: SELECT * FROM users WHERE id = ?"
        
        return {
            "immediate_actions": immediate_actions,
            "long_term_solutions": long_term_solutions,
            "code_examples": code_examples,
            "testing_recommendations": [
                "Implement automated security testing in CI/CD pipeline",
                "Regular penetration testing",
                "Code security reviews"
            ],
            "monitoring_suggestions": [
                "Implement WAF (Web Application Firewall)",
                "Monitor for suspicious patterns in logs",
                "Set up security alerts for anomalous behavior"
            ]
        }
