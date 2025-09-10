from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, red, green, orange
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
import os
from typing import Dict, List, Any

class ReportGenerator:
    def __init__(self):
        """Initialize the report generator"""
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_custom_styles()
        
    def _create_custom_styles(self):
        """Create custom styles for the report"""
        styles = {}
        
        # Title style
        styles['CustomTitle'] = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1f2937'),
            alignment=TA_CENTER
        )
        
        # Heading styles
        styles['CustomHeading1'] = ParagraphStyle(
            'CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            textColor=HexColor('#374151'),
            borderWidth=1,
            borderColor=HexColor('#e5e7eb'),
            borderPadding=5
        )
        
        styles['CustomHeading2'] = ParagraphStyle(
            'CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            textColor=HexColor('#4b5563')
        )
        
        # Body text
        styles['CustomBody'] = ParagraphStyle(
            'CustomBody',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            alignment=TA_JUSTIFY,
            textColor=HexColor('#374151')
        )
        
        # Code style
        styles['Code'] = ParagraphStyle(
            'Code',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=9,
            textColor=HexColor('#1f2937'),
            backColor=HexColor('#f3f4f6'),
            borderWidth=1,
            borderColor=HexColor('#d1d5db'),
            borderPadding=4
        )
        
        return styles

    def generate_pdf_report(self, scan_results: Dict[str, Any], output_path: str) -> bool:
        """
        Generate a comprehensive PDF report from scan results
        
        Args:
            scan_results: Dictionary containing scan results
            output_path: Path where the PDF should be saved
            
        Returns:
            bool: True if report generated successfully, False otherwise
        """
        try:
            # Create the PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build the story (content)
            story = []
            
            # Title page
            story.extend(self._create_title_page(scan_results))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(scan_results))
            story.append(Spacer(1, 12))
            
            # Scan overview
            story.extend(self._create_scan_overview(scan_results))
            story.append(Spacer(1, 12))
            
            # Detailed findings
            story.extend(self._create_detailed_findings(scan_results))
            story.append(Spacer(1, 12))
            
            # AI Analysis (if available)
            if scan_results.get('ai_analysis'):
                story.extend(self._create_ai_analysis_section(scan_results['ai_analysis']))
                story.append(Spacer(1, 12))
            
            # Recommendations
            story.extend(self._create_recommendations_section(scan_results))
            story.append(Spacer(1, 12))
            
            # Appendices
            story.extend(self._create_appendices(scan_results))
            
            # Build the PDF
            doc.build(story)
            
            print(f"[+] PDF report generated successfully: {output_path}")
            return True
            
        except Exception as e:
            print(f"[!] Error generating PDF report: {str(e)}")
            return False

    def _create_title_page(self, scan_results: Dict[str, Any]) -> List:
        """Create the title page content"""
        story = []
        
        # Main title
        title = Paragraph("Cybersecurity Scan Report", self.custom_styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 30))
        
        # Target information
        target_url = scan_results.get('target_url', 'Unknown')
        target_info = Paragraph(f"<b>Target:</b> {target_url}", self.custom_styles['CustomHeading2'])
        story.append(target_info)
        story.append(Spacer(1, 12))
        
        # Scan date
        scan_date = scan_results.get('timestamp', datetime.now().isoformat())
        if isinstance(scan_date, str):
            try:
                scan_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                scan_date_str = scan_date.strftime("%B %d, %Y at %I:%M %p")
            except:
                scan_date_str = scan_date
        else:
            scan_date_str = str(scan_date)
            
        date_info = Paragraph(f"<b>Scan Date:</b> {scan_date_str}", self.custom_styles['CustomBody'])
        story.append(date_info)
        story.append(Spacer(1, 12))
        
        # Summary statistics
        summary = scan_results.get('summary', {})
        total_urls = summary.get('total_urls_scanned', 0)
        total_vulns = summary.get('total_vulnerabilities', 0)
        
        stats_data = [
            ['Metric', 'Value'],
            ['URLs Scanned', str(total_urls)],
            ['Vulnerabilities Found', str(total_vulns)],
            ['Risk Level', scan_results.get('ai_analysis', {}).get('risk_level', 'Unknown')]
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#374151')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f9fafb')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e5e7eb'))
        ]))
        
        story.append(stats_table)
        
        return story

    def _create_executive_summary(self, scan_results: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.custom_styles['CustomHeading1']))
        
        # Get AI analysis summary or create a basic one
        ai_analysis = scan_results.get('ai_analysis', {})
        executive_summary = ai_analysis.get('executive_summary')
        
        if not executive_summary:
            # Generate basic summary
            summary = scan_results.get('summary', {})
            total_vulns = summary.get('total_vulnerabilities', 0)
            
            if total_vulns == 0:
                executive_summary = "The security scan completed successfully with no critical vulnerabilities detected. The target application appears to have basic security measures in place."
            else:
                executive_summary = f"The security scan identified {total_vulns} vulnerabilities that require immediate attention. These findings indicate potential security risks that could be exploited by malicious actors."
        
        summary_para = Paragraph(executive_summary, self.custom_styles['CustomBody'])
        story.append(summary_para)
        
        return story

    def _create_scan_overview(self, scan_results: Dict[str, Any]) -> List:
        """Create scan overview section"""
        story = []
        
        story.append(Paragraph("Scan Overview", self.custom_styles['CustomHeading1']))
        
        # Scan configuration
        scan_types = scan_results.get('scan_types', [])
        crawl_enabled = scan_results.get('crawl_enabled', False)
        
        overview_text = f"""
        This automated security assessment was performed using advanced vulnerability scanning techniques.
        The scan included the following tests:
        
        • Vulnerability Types: {', '.join(scan_types).upper() if scan_types else 'None specified'}
        • Web Crawling: {'Enabled' if crawl_enabled else 'Disabled'}
        • AI Analysis: {'Enabled' if scan_results.get('ai_analysis') else 'Disabled'}
        
        The assessment focused on identifying common web application security vulnerabilities
        including Cross-Site Scripting (XSS) and SQL Injection attacks.
        """
        
        overview_para = Paragraph(overview_text, self.custom_styles['CustomBody'])
        story.append(overview_para)
        
        return story

    def _create_detailed_findings(self, scan_results: Dict[str, Any]) -> List:
        """Create detailed findings section"""
        story = []
        
        story.append(Paragraph("Detailed Findings", self.custom_styles['CustomHeading1']))
        
        results = scan_results.get('results', [])
        
        if not results:
            no_results = Paragraph("No scan results available.", self.custom_styles['CustomBody'])
            story.append(no_results)
            return story
        
        for i, result in enumerate(results, 1):
            url = result.get('url', 'Unknown URL')
            
            # URL heading
            url_heading = Paragraph(f"URL {i}: {url}", self.custom_styles['CustomHeading2'])
            story.append(url_heading)
            
            # Check for vulnerabilities
            has_vulns = False
            
            # XSS Results
            xss_results = result.get('xss_results', {})
            if xss_results.get('vulnerable', False):
                has_vulns = True
                story.extend(self._create_vulnerability_section("Cross-Site Scripting (XSS)", xss_results))
            
            # SQL Injection Results
            sqli_results = result.get('sqli_results', {})
            if sqli_results.get('vulnerable', False):
                has_vulns = True
                story.extend(self._create_vulnerability_section("SQL Injection", sqli_results))
            
            if not has_vulns:
                safe_msg = Paragraph("✓ No vulnerabilities detected for this URL", self.custom_styles['CustomBody'])
                story.append(safe_msg)
            
            story.append(Spacer(1, 12))
        
        return story

    def _create_vulnerability_section(self, vuln_type: str, results: Dict[str, Any]) -> List:
        """Create a section for specific vulnerability type"""
        story = []
        
        vuln_title = Paragraph(f"⚠ {vuln_type} Vulnerabilities", self.custom_styles['CustomHeading2'])
        story.append(vuln_title)
        
        vulnerabilities = results.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            vuln_data = [
                ['Property', 'Value'],
                ['Type', vuln.get('type', 'Unknown')],
                ['Parameter', vuln.get('parameter', 'N/A')],
                ['Severity', vuln.get('severity', 'Medium')],
                ['Method', vuln.get('method', 'GET')]
            ]
            
            if vuln.get('payload'):
                vuln_data.append(['Payload', vuln.get('payload')])
            
            if vuln.get('evidence'):
                vuln_data.append(['Evidence', vuln.get('evidence')])
            
            vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4*inch])
            
            # Color code by severity
            severity = vuln.get('severity', 'Medium').lower()
            if severity == 'high':
                header_color = HexColor('#dc2626')
            elif severity == 'medium':
                header_color = HexColor('#d97706')
            else:
                header_color = HexColor('#16a34a')
            
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), header_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f9fafb')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#e5e7eb')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 8))
        
        return story

    def _create_ai_analysis_section(self, ai_analysis: Dict[str, Any]) -> List:
        """Create AI analysis section"""
        story = []
        
        story.append(Paragraph("AI Security Analysis", self.custom_styles['CustomHeading1']))
        
        # Risk assessment
        risk_level = ai_analysis.get('risk_level', 'Unknown')
        risk_para = Paragraph(f"<b>Risk Level:</b> {risk_level}", self.custom_styles['CustomHeading2'])
        story.append(risk_para)
        story.append(Spacer(1, 8))
        
        # Recommendations
        recommendations = ai_analysis.get('recommendations', [])
        if recommendations:
            rec_title = Paragraph("AI Recommendations:", self.custom_styles['CustomHeading2'])
            story.append(rec_title)
            
            for rec in recommendations:
                priority = rec.get('priority', 'Medium')
                action = rec.get('action', 'No action specified')
                
                rec_text = f"• <b>{priority} Priority:</b> {action}"
                rec_para = Paragraph(rec_text, self.custom_styles['CustomBody'])
                story.append(rec_para)
        
        # Technical details
        tech_details = ai_analysis.get('technical_details', {})
        if tech_details:
            story.append(Spacer(1, 12))
            tech_title = Paragraph("Technical Analysis:", self.custom_styles['CustomHeading2'])
            story.append(tech_title)
            
            most_common = tech_details.get('most_common_vulnerability', 'None')
            urls_scanned = tech_details.get('total_urls_scanned', 0)
            
            tech_text = f"Most common vulnerability type: {most_common}<br/>Total URLs analyzed: {urls_scanned}"
            tech_para = Paragraph(tech_text, self.custom_styles['CustomBody'])
            story.append(tech_para)
        
        return story

    def _create_recommendations_section(self, scan_results: Dict[str, Any]) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Security Recommendations", self.custom_styles['CustomHeading1']))
        
        # Get AI recommendations or provide generic ones
        ai_analysis = scan_results.get('ai_analysis', {})
        recommendations = ai_analysis.get('recommendations', [])
        
        if not recommendations:
            # Provide generic recommendations based on findings
            total_vulns = scan_results.get('summary', {}).get('total_vulnerabilities', 0)
            
            if total_vulns > 0:
                generic_recs = [
                    "Implement input validation and output encoding for all user inputs",
                    "Use parameterized queries to prevent SQL injection attacks",
                    "Deploy a Web Application Firewall (WAF) for additional protection",
                    "Conduct regular security assessments and penetration testing",
                    "Implement security headers (CSP, HSTS, X-Frame-Options)",
                    "Keep all software components and frameworks up to date"
                ]
            else:
                generic_recs = [
                    "Continue regular security assessments to maintain security posture",
                    "Implement additional security monitoring and logging",
                    "Consider implementing advanced security measures like CSP",
                    "Conduct periodic penetration testing by qualified professionals"
                ]
            
            for rec in generic_recs:
                rec_para = Paragraph(f"• {rec}", self.custom_styles['CustomBody'])
                story.append(rec_para)
        else:
            for rec in recommendations:
                priority = rec.get('priority', 'Medium')
                action = rec.get('action', 'No action specified')
                
                rec_text = f"• <b>{priority} Priority:</b> {action}"
                rec_para = Paragraph(rec_text, self.custom_styles['CustomBody'])
                story.append(rec_para)
        
        return story

    def _create_appendices(self, scan_results: Dict[str, Any]) -> List:
        """Create appendices section"""
        story = []
        
        story.append(Paragraph("Appendices", self.custom_styles['CustomHeading1']))
        
        # Scan configuration details
        story.append(Paragraph("A. Scan Configuration", self.custom_styles['CustomHeading2']))
        
        config_data = [
            ['Parameter', 'Value'],
            ['Target URL', scan_results.get('target_url', 'Unknown')],
            ['Scan Types', ', '.join(scan_results.get('scan_types', []))],
            ['Crawling Enabled', 'Yes' if scan_results.get('crawl_enabled') else 'No'],
            ['AI Analysis', 'Yes' if scan_results.get('ai_analysis') else 'No'],
            ['Scan Duration', scan_results.get('summary', {}).get('scan_duration', 'Unknown')]
        ]
        
        config_table = Table(config_data, colWidths=[2*inch, 3*inch])
        config_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#374151')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f9fafb')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e5e7eb'))
        ]))
        
        story.append(config_table)
        story.append(Spacer(1, 12))
        
        # Disclaimer
        story.append(Paragraph("B. Disclaimer", self.custom_styles['CustomHeading2']))
        disclaimer_text = """
        This security assessment is based on automated scanning techniques and may not identify all potential vulnerabilities.
        Manual security testing and code review by qualified security professionals is recommended for comprehensive security assessment.
        The findings in this report should be verified and addressed according to your organization's security policies and procedures.
        """
        
        disclaimer_para = Paragraph(disclaimer_text, self.custom_styles['CustomBody'])
        story.append(disclaimer_para)
        
        return story
