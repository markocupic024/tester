
#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Callable, Tuple
from enum import Enum
import requests
from urllib.parse import urlparse
import warnings
import dns.resolver
import html

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, HRFlowable
)
from reportlab.pdfgen import canvas

warnings.filterwarnings('ignore')


class Colors:
    PRIMARY = colors.HexColor('#2563EB')
    PRIMARY_DARK = colors.HexColor('#1D4ED8')
    PRIMARY_LIGHT = colors.HexColor('#DBEAFE')

    CRITICAL = colors.HexColor('#DC2626')
    HIGH = colors.HexColor('#EA580C')
    MEDIUM = colors.HexColor('#D97706')
    LOW = colors.HexColor('#2563EB')
    INFO = colors.HexColor('#6B7280')
    SUCCESS = colors.HexColor('#059669')

    BG_LIGHT = colors.HexColor('#F8FAFC')
    BG_DARK = colors.HexColor('#1E293B')
    BG_CARD = colors.HexColor('#FFFFFF')

    TEXT_PRIMARY = colors.HexColor('#0F172A')
    TEXT_SECONDARY = colors.HexColor('#475569')
    TEXT_MUTED = colors.HexColor('#94A3B8')
    TEXT_WHITE = colors.HexColor('#FFFFFF')

    BORDER = colors.HexColor('#E2E8F0')
    BORDER_LIGHT = colors.HexColor('#F1F5F9')


class TestPhase(Enum):
    QUICK = "quick"
    MEDIUM = "medium"
    SECURITY_SCAN = "security"
    PERFORMANCE = "performance"


class PDFReportGenerator:

    def __init__(self, results: Dict[str, Any], output_file: str):
        self.results = results
        self.output_file = output_file
        self.styles = self._create_styles()
        self.page_width, self.page_height = letter
        self.margin = 0.75 * inch
        self.content_width = self.page_width - 2 * self.margin
        
    def _create_styles(self) -> Dict[str, ParagraphStyle]:
        base_styles = getSampleStyleSheet()
        
        return {
            'title': ParagraphStyle(
                'Title',
                parent=base_styles['Heading1'],
                fontSize=28,
                textColor=Colors.TEXT_WHITE,
                spaceAfter=6,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'subtitle': ParagraphStyle(
                'Subtitle',
                parent=base_styles['Normal'],
                fontSize=12,
                textColor=colors.HexColor('#CBD5E1'),
                alignment=TA_CENTER,
                spaceAfter=20
            ),
            'section_header': ParagraphStyle(
                'SectionHeader',
                parent=base_styles['Heading2'],
                fontSize=18,
                textColor=Colors.PRIMARY,
                spaceBefore=20,
                spaceAfter=12,
                fontName='Helvetica-Bold',
                borderPadding=10
            ),
            'subsection': ParagraphStyle(
                'Subsection',
                parent=base_styles['Heading3'],
                fontSize=14,
                textColor=Colors.TEXT_PRIMARY,
                spaceBefore=12,
                spaceAfter=8,
                fontName='Helvetica-Bold'
            ),
            'body': ParagraphStyle(
                'Body',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=Colors.TEXT_PRIMARY,
                spaceAfter=6,
                leading=14
            ),
            'body_small': ParagraphStyle(
                'BodySmall',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=Colors.TEXT_SECONDARY,
                spaceAfter=4,
                leading=12
            ),
            'code': ParagraphStyle(
                'Code',
                parent=base_styles['Normal'],
                fontSize=8,
                textColor=Colors.TEXT_SECONDARY,
                fontName='Courier',
                backColor=Colors.BG_LIGHT,
                spaceAfter=4,
                leftIndent=10,
                rightIndent=10
            ),
            'badge_critical': ParagraphStyle(
                'BadgeCritical',
                fontSize=9,
                textColor=Colors.TEXT_WHITE,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'metric_value': ParagraphStyle(
                'MetricValue',
                fontSize=24,
                textColor=Colors.PRIMARY,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'metric_label': ParagraphStyle(
                'MetricLabel',
                fontSize=9,
                textColor=Colors.TEXT_SECONDARY,
                alignment=TA_CENTER
            ),
            'footer': ParagraphStyle(
                'Footer',
                fontSize=8,
                textColor=Colors.TEXT_MUTED,
                alignment=TA_CENTER
            )
        }

    def generate(self):
        doc = SimpleDocTemplate(
            self.output_file,
            pagesize=letter,
            leftMargin=self.margin,
            rightMargin=self.margin,
            topMargin=self.margin,
            bottomMargin=self.margin
        )
        
        story = []
        
        # Build report sections
        story.extend(self._create_header())
        story.extend(self._create_executive_dashboard())
        
        # Collect sections that have content
        sections = []
        if self._has_results('security_headers') or self._has_results('ssl'):
            sections.append(self._create_security_section())
        if self._has_results('pa11y'):
            sections.append(self._create_accessibility_section())
        if self._has_results('owasp_zap') or self._has_results('nuclei'):
            sections.append(self._create_vulnerability_section())
        if self._has_results('w3c_validator'):
            sections.append(self._create_validation_section())
        if self._has_results('robots_sitemap') or self._has_results('dns'):
            sections.append(self._create_seo_section())
        
        # Add sections with page breaks only between them
        for i, section in enumerate(sections):
            if i == 0:
                story.append(PageBreak())
            story.extend(section)
            if i < len(sections) - 1:
                story.append(PageBreak())
        
        # Build with custom page template
        doc.build(story, onFirstPage=self._add_page_decorations, 
                  onLaterPages=self._add_page_decorations)
        
        print(f"PDF report generated: {self.output_file}")

    def _has_results(self, key: str) -> bool:
        if key not in self.results:
            return False
        result = self.results[key]
        if isinstance(result, dict):
            if 'error' in result and len(result) == 1:
                return False
            if not result:
                return False
        return True

    def _add_page_decorations(self, canvas_obj: canvas.Canvas, doc):
        canvas_obj.saveState()

        canvas_obj.setFillColor(Colors.PRIMARY)
        canvas_obj.setFillColor(Colors.PRIMARY)
        canvas_obj.rect(0, self.page_height - 8, self.page_width, 8, fill=True, stroke=False)
        
        # Footer
        canvas_obj.setFillColor(Colors.TEXT_MUTED)
        canvas_obj.setFont('Helvetica', 8)
        
        # Page number
        page_num = canvas_obj.getPageNumber()
        canvas_obj.drawCentredString(self.page_width / 2, 0.4 * inch, f"Page {page_num}")
        
        # Timestamp
        canvas_obj.drawString(
            self.margin, 0.4 * inch,
            f"Generated: {self.results.get('timestamp', 'N/A')}"
        )
        
        # URL on right
        url = self.results.get('url', '')
        canvas_obj.drawRightString(self.page_width - self.margin, 0.4 * inch, url)
        
        canvas_obj.restoreState()

    def _create_header(self) -> List:
        elements = []

        header_data = [['']]
        header_data = [['']]
        header_table = Table(header_data, colWidths=[self.content_width], rowHeights=[120])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), Colors.BG_DARK),
            ('TOPPADDING', (0, 0), (-1, -1), 30),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 30),
            ('LEFTPADDING', (0, 0), (-1, -1), 20),
            ('RIGHTPADDING', (0, 0), (-1, -1), 20),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        # Overlay content
        title = Paragraph("Website Analysis Report", self.styles['title'])
        
        url = self.results.get('url', 'Unknown')
        subtitle = Paragraph(f"Comprehensive testing results for<br/><b>{url}</b>", self.styles['subtitle'])
        
        # Create header content
        content_data = [[title], [subtitle]]
        content_table = Table(content_data, colWidths=[self.content_width - 40])
        content_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        # Wrap in dark background
        wrapper_data = [[content_table]]
        wrapper = Table(wrapper_data, colWidths=[self.content_width], rowHeights=[130])
        wrapper.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), Colors.BG_DARK),
            ('TOPPADDING', (0, 0), (-1, -1), 25),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 25),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 0, Colors.BG_DARK),
        ]))
        
        elements.append(wrapper)
        elements.append(Spacer(1, 40))
        
        return elements

    def _create_metric_card(self, value: str, label: str, color: colors.Color = Colors.PRIMARY) -> Table:
        value_style = ParagraphStyle(
            'MetricValue',
            fontSize=28,
            textColor=color,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        data = [
            [Paragraph(str(value), value_style)],
            [Paragraph(label, self.styles['metric_label'])]
        ]
        
        card = Table(data, colWidths=[1.4 * inch])
        card.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), Colors.BG_CARD),
            ('BOX', (0, 0), (-1, -1), 1, Colors.BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        return card

    def _create_executive_dashboard(self) -> List:
        elements = []

        elements.append(Paragraph("Executive Summary", self.styles['section_header']))
        
        # Collect metrics
        metrics = []
        
        # Security grade
        if self._has_results('security_headers'):
            grade = self.results['security_headers'].get('grade', 'N/A')
            color = Colors.SUCCESS if grade in ['A+', 'A', 'A-', 'B+', 'B'] else Colors.MEDIUM if grade in ['B-', 'C+', 'C'] else Colors.HIGH
            metrics.append(self._create_metric_card(grade, "Security Grade", color))
        
        # SSL Status
        if self._has_results('ssl'):
            ssl = self.results['ssl']
            ssl_ok = ssl.get('certificate_valid', False)
            metrics.append(self._create_metric_card(
                "Valid" if ssl_ok else "Invalid",
                "SSL Certificate",
                Colors.SUCCESS if ssl_ok else Colors.CRITICAL
            ))
        
        # Accessibility issues
        if self._has_results('pa11y'):
            issues = self.results['pa11y'].get('total_issues', 0)
            color = Colors.SUCCESS if issues == 0 else Colors.MEDIUM if issues < 10 else Colors.HIGH
            metrics.append(self._create_metric_card(str(issues), "A11y Issues", color))
        
        # HTML Errors
        if self._has_results('w3c_validator'):
            errors = self.results['w3c_validator'].get('summary', {}).get('errors', 0)
            color = Colors.SUCCESS if errors == 0 else Colors.MEDIUM if errors < 5 else Colors.HIGH
            metrics.append(self._create_metric_card(str(errors), "HTML Errors", color))
        
        # Security alerts (ZAP)
        if self._has_results('owasp_zap'):
            alerts = self.results['owasp_zap'].get('total_alerts', 0)
            high = self.results['owasp_zap'].get('summary', {}).get('high', 0)
            color = Colors.SUCCESS if alerts == 0 else Colors.CRITICAL if high > 0 else Colors.MEDIUM
            metrics.append(self._create_metric_card(str(alerts), "Security Alerts", color))
        
        # Nuclei findings
        if self._has_results('nuclei'):
            vulns = self.results['nuclei'].get('total_vulnerabilities', 0)
            critical = self.results['nuclei'].get('summary', {}).get('critical', 0)
            high = self.results['nuclei'].get('summary', {}).get('high', 0)
            color = Colors.SUCCESS if vulns == 0 else Colors.CRITICAL if (critical + high) > 0 else Colors.MEDIUM
            metrics.append(self._create_metric_card(str(vulns), "Vuln Findings", color))
        
        # Create metrics row
        if metrics:
            # Create table with all metrics (no truncation)
            # ReportLab Table expects list of rows, each row is list of cells
            # We'll create one row with all metrics
            num_cols = len(metrics)
            metrics_table = Table([metrics], colWidths=[1.5 * inch] * num_cols)
            metrics_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ]))
            elements.append(metrics_table)
        
        elements.append(Spacer(1, 20))
        
        # Quick status summary
        elements.append(Paragraph("Quick Status", self.styles['subsection']))
        
        status_items = []
        
        # Lighthouse note
        if self._has_results('lighthouse') and self.results['lighthouse'].get('success'):
            status_items.append(("Lighthouse Report", "Available as separate HTML file", Colors.SUCCESS))
        
        # Security headers
        if self._has_results('security_headers'):
            sh = self.results['security_headers']
            missing = len(sh.get('missing_headers', []))
            if missing == 0:
                status_items.append(("Security Headers", "All headers present", Colors.SUCCESS))
            else:
                status_items.append(("Security Headers", f"{missing} headers missing", Colors.MEDIUM))
        
        # SSL/TLS
        if self._has_results('ssl'):
            ssl = self.results['ssl']
            if ssl.get('weak_protocols'):
                status_items.append(("SSL/TLS", f"Weak protocols: {', '.join(ssl['weak_protocols'])}", Colors.HIGH))
            elif ssl.get('supports_tls_1_3'):
                status_items.append(("SSL/TLS", "TLS 1.3 supported", Colors.SUCCESS))
            elif ssl.get('supports_tls_1_2'):
                status_items.append(("SSL/TLS", "TLS 1.2 supported", Colors.SUCCESS))
        
        # Robots/Sitemap
        if self._has_results('robots_sitemap'):
            rs = self.results['robots_sitemap']
            robots_ok = rs.get('robots_txt', {}).get('exists', False)
            sitemap_ok = rs.get('sitemap', {}).get('exists', False)
            if robots_ok and sitemap_ok:
                status_items.append(("SEO Files", "robots.txt & sitemap present", Colors.SUCCESS))
            elif robots_ok or sitemap_ok:
                status_items.append(("SEO Files", "Partially configured", Colors.MEDIUM))
            else:
                status_items.append(("SEO Files", "Missing robots.txt & sitemap", Colors.HIGH))
        
        # Build status table
        if status_items:
            status_data = []
            for item, status, color in status_items:
                indicator = "•"
                indicator_style = ParagraphStyle('Indicator', fontSize=12, textColor=color)
                status_data.append([
                    Paragraph(indicator, indicator_style),
                    Paragraph(f"<b>{item}</b>", self.styles['body']),
                    Paragraph(status, self.styles['body_small'])
                ])
            
            status_table = Table(status_data, colWidths=[0.3 * inch, 2 * inch, 4 * inch])
            status_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(status_table)
        
        return elements

    def _create_severity_badge(self, severity: str) -> Paragraph:
        severity_lower = severity.lower()
        color_map = {
            'critical': Colors.CRITICAL,
            'high': Colors.HIGH,
            'medium': Colors.MEDIUM,
            'low': Colors.LOW,
            'info': Colors.INFO,
            'informational': Colors.INFO,
            'error': Colors.HIGH,
            'warning': Colors.MEDIUM,
            'notice': Colors.INFO
        }
        color = color_map.get(severity_lower, Colors.INFO)
        
        style = ParagraphStyle(
            'Badge',
            fontSize=8,
            textColor=Colors.TEXT_WHITE,
            backColor=color,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            leftIndent=4,
            rightIndent=4,
            spaceBefore=2,
            spaceAfter=2
        )
        
        return Paragraph(f" {severity.upper()} ", style)

    def _create_section_divider(self, title: str, icon: str = "") -> List:
        elements = []
        elements.append(Spacer(1, 15))
        elements.append(HRFlowable(
            width="100%",
            thickness=1,
            color=Colors.BORDER,
            spaceBefore=10,
            spaceAfter=10
        ))
        
        elements.append(Paragraph(f"{icon} {title}", self.styles['section_header']))
        
        return elements

    def _create_security_section(self) -> List:
        elements = self._create_section_divider("Security Analysis")

        if self._has_results('security_headers'):
            sh = self.results['security_headers']
            
            elements.append(Paragraph("<b>Security Headers (Mozilla Observatory)</b>", self.styles['subsection']))
            
            # Grade display
            grade = sh.get('grade', 'N/A')
            score = sh.get('score', 'N/A')
            
            grade_text = f"<b>Grade: {grade}</b> &nbsp;&nbsp;|&nbsp;&nbsp; Score: {score}/100"
            elements.append(Paragraph(grade_text, self.styles['body']))
            elements.append(Spacer(1, 8))
            
            # Headers table
            headers = sh.get('headers', {})
            if headers:
                header_data = [
                    [Paragraph("<b>Header</b>", self.styles['body']),
                     Paragraph("<b>Status</b>", self.styles['body'])]
                ]
                
                for header, value in headers.items():
                    if value == 'Missing':
                        status = Paragraph("Missing", self.styles['body'])
                    else:
                        status = Paragraph("Present", self.styles['body'])
                    header_data.append([
                        Paragraph(header, self.styles['body_small']),
                        status
                    ])
                
                header_table = Table(header_data, colWidths=[4 * inch, 2 * inch])
                header_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), Colors.BG_LIGHT),
                    ('GRID', (0, 0), (-1, -1), 0.5, Colors.BORDER),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ]))
                elements.append(header_table)
            
            elements.append(Spacer(1, 15))
        
        # SSL/TLS Analysis
        if self._has_results('ssl'):
            ssl = self.results['ssl']
            
            elements.append(Paragraph("<b>SSL/TLS Configuration</b>", self.styles['subsection']))
            
            # Certificate status
            cert_valid = ssl.get('certificate_valid', False)
            cert_status = "Valid" if cert_valid else "Invalid"
            elements.append(Paragraph(f"<b>Certificate:</b> {cert_status}", self.styles['body']))
            
            # Certificate details
            cert_details = ssl.get('certificate_details', {})
            if cert_details:
                elements.append(Paragraph(
                    f"Expires: {cert_details.get('not_valid_after', 'N/A')}",
                    self.styles['body_small']
                ))
            
            # TLS versions
            tls_status = []
            if ssl.get('supports_tls_1_3'):
                tls_status.append("TLS 1.3")
            if ssl.get('supports_tls_1_2'):
                tls_status.append("TLS 1.2")
            if tls_status:
                elements.append(Paragraph(f"<b>Protocols:</b> {' | '.join(tls_status)}", self.styles['body']))
            
            # Weak protocols warning
            weak = ssl.get('weak_protocols', [])
            if weak:
                elements.append(Paragraph(
                    f"<b>Warning:</b> Weak protocols enabled: {', '.join(weak)}",
                    self.styles['body']
                ))

            if ssl.get('has_weak_ciphers'):
                elements.append(Paragraph(
                    "<b>Warning:</b> Weak cipher suites detected",
                    self.styles['body']
                ))

        return elements

    def _create_accessibility_section(self) -> List:
        elements = self._create_section_divider("Accessibility Analysis")
        
        pa11y = self.results.get('pa11y', {})
        
        if pa11y.get('error'):
            elements.append(Paragraph(
                f"Error running accessibility tests: {pa11y['error']}",
                self.styles['body']
            ))
            return elements
        
        total = pa11y.get('total_issues', 0)
        summary = pa11y.get('summary', {})
        
        # Summary stats
        elements.append(Paragraph(
            f"<b>Total Issues Found: {total}</b>",
            self.styles['body']
        ))
        
        if summary:
            elements.append(Paragraph(
                f"Errors: {summary.get('errors', 0)} | "
                f"Warnings: {summary.get('warnings', 0)} | "
                f"Notices: {summary.get('notices', 0)}",
                self.styles['body_small']
            ))
        
        elements.append(Spacer(1, 10))
        
        issues = pa11y.get('issues', [])
        
        if not issues:
            elements.append(Paragraph(
                "<b>No accessibility issues found!</b>",
                self.styles['body']
            ))
            return elements
        
        # Group issues by type
        errors = [i for i in issues if i.get('type') == 'error']
        warnings = [i for i in issues if i.get('type') == 'warning']
        notices = [i for i in issues if i.get('type') == 'notice']
        
        # Display errors
        if errors:
            elements.append(Paragraph(f"<b>Errors ({len(errors)})</b>", self.styles['subsection']))
            
            for i, issue in enumerate(errors, 1):
                msg = html.escape(issue.get('message', 'Unknown issue'))
                elements.append(Paragraph(f"<b>{i}.</b> {msg}", self.styles['body']))
                
                selector = issue.get('selector', '')
                if selector:
                    elements.append(Paragraph(
                        f"<font color='#64748B'>Element: {html.escape(selector)}</font>",
                        self.styles['code']
                    ))
                elements.append(Spacer(1, 4))
        
        # Display warnings
        if warnings:
            elements.append(Paragraph(f"<b>Warnings ({len(warnings)})</b>", self.styles['subsection']))
            for i, issue in enumerate(warnings, 1):
                msg = html.escape(issue.get('message', 'Unknown issue'))
                elements.append(Paragraph(f"{i}. {msg}", self.styles['body_small']))
        
        # Display notices count
        if notices:
            elements.append(Paragraph(
                f"<i>Plus {len(notices)} informational notices</i>",
                self.styles['body_small']
            ))

        return elements

    def _create_vulnerability_section(self) -> List:
        elements = self._create_section_divider("Security Scan Results")

        if self._has_results('owasp_zap'):
            zap = self.results['owasp_zap']
            
            elements.append(Paragraph("<b>OWASP ZAP Baseline Scan</b>", self.styles['subsection']))
            
            total = zap.get('total_alerts', 0)
            summary = zap.get('summary', {})
            
            # Summary bar
            summary_text = (
                f"<b>Total: {total}</b> &nbsp;|&nbsp; "
                f"<font color='#DC2626'>High: {summary.get('high', 0)}</font> &nbsp;|&nbsp; "
                f"<font color='#D97706'>Medium: {summary.get('medium', 0)}</font> &nbsp;|&nbsp; "
                f"<font color='#2563EB'>Low: {summary.get('low', 0)}</font> &nbsp;|&nbsp; "
                f"<font color='#6B7280'>Info: {summary.get('info', 0)}</font>"
            )
            elements.append(Paragraph(summary_text, self.styles['body']))
            elements.append(Spacer(1, 10))
            
            alerts = zap.get('alerts', [])
            if alerts:
                # Color map for severity
                color_map = {
                    'High': '#DC2626',
                    'Critical': '#DC2626',
                    'Medium': '#D97706',
                    'Low': '#2563EB',
                    'Informational': '#6B7280'
                }
                
                # Show detailed alerts
                for i, alert in enumerate(alerts, 1):
                    name = html.escape(alert.get('name', 'Unknown'))
                    risk = alert.get('risk', 'Unknown')
                    confidence = alert.get('confidence', '')
                    count = alert.get('count', 0)
                    color = color_map.get(risk, '#6B7280')
                    
                    # Alert header with severity
                    elements.append(Paragraph(
                        f"<b>{i}.</b> <font color='{color}'>[{risk}]</font> {name}",
                        self.styles['body']
                    ))
                    
                    # Plugin ID and confidence
                    plugin_id = alert.get('id', '')
                    meta_parts = []
                    if plugin_id:
                        meta_parts.append(f"Plugin: {plugin_id}")
                    if confidence:
                        meta_parts.append(f"Confidence: {confidence}")
                    if count > 0:
                        meta_parts.append(f"Instances: {count}")
                    if meta_parts:
                        elements.append(Paragraph(
                            f"<font color='#64748B'>{' | '.join(meta_parts)}</font>",
                            self.styles['code']
                        ))
                    
                    # CWE/WASC IDs if available
                    cweid = alert.get('cweid', '')
                    wascid = alert.get('wascid', '')
                    if cweid or wascid:
                        ids_parts = []
                        if cweid and cweid != '0':
                            ids_parts.append(f"CWE-{cweid}")
                        if wascid and wascid != '0':
                            ids_parts.append(f"WASC-{wascid}")
                        if ids_parts:
                            elements.append(Paragraph(
                                f"<font color='#7C3AED'>{', '.join(ids_parts)}</font>",
                                self.styles['code']
                            ))
                    
                    # URLs where found - show all URLs
                    urls = alert.get('urls', [])
                    if urls:
                        for url in urls:
                            elements.append(Paragraph(
                                f"<font color='#059669'>Found at: {html.escape(url)}</font>",
                                self.styles['code']
                            ))
                    
                    # Description (full text, cleaned up)
                    desc = alert.get('description', '')
                    if desc:
                        # Strip HTML tags from description
                        clean_desc = re.sub(r'<[^>]+>', '', desc)
                        clean_desc = clean_desc.strip()
                        if clean_desc:
                            elements.append(Paragraph(
                                f"<i>{html.escape(clean_desc)}</i>",
                                self.styles['body_small']
                            ))
                    
                    # Solution (full text)
                    solution = alert.get('solution', '')
                    if solution:
                        clean_sol = re.sub(r'<[^>]+>', '', solution)
                        clean_sol = clean_sol.strip()
                        if clean_sol:
                            elements.append(Paragraph(
                                f"<font color='#0284C7'><b>Fix:</b> {html.escape(clean_sol)}</font>",
                                self.styles['code']
                            ))
                    
                    elements.append(Spacer(1, 8))
            else:
                elements.append(Paragraph("No security alerts found", self.styles['body']))
            
            elements.append(Spacer(1, 15))
        
        # Nuclei
        if self._has_results('nuclei'):
            nuclei = self.results['nuclei']
            
            elements.append(Paragraph("<b>Nuclei Vulnerability Scanner</b>", self.styles['subsection']))
            
            total = nuclei.get('total_vulnerabilities', 0)
            summary = nuclei.get('summary', {})
            
            # Summary
            summary_text = (
                f"<b>Total: {total}</b> &nbsp;|&nbsp; "
                f"<font color='#DC2626'>Critical: {summary.get('critical', 0)}</font> &nbsp;|&nbsp; "
                f"<font color='#EA580C'>High: {summary.get('high', 0)}</font> &nbsp;|&nbsp; "
                f"<font color='#D97706'>Medium: {summary.get('medium', 0)}</font> &nbsp;|&nbsp; "
                f"<font color='#2563EB'>Low: {summary.get('low', 0)}</font> &nbsp;|&nbsp; "
                f"<font color='#6B7280'>Info: {summary.get('info', 0)}</font>"
            )
            elements.append(Paragraph(summary_text, self.styles['body']))
            elements.append(Spacer(1, 10))
            
            vulns = nuclei.get('vulnerabilities', [])
            if vulns:
                for i, vuln in enumerate(vulns, 1):
                    severity = (vuln.get('severity') or 'unknown').upper()
                    name = vuln.get('name', 'Unknown')
                    template_id = vuln.get('template_id', '')
                    
                    # Color code by severity
                    color_map = {
                        'CRITICAL': '#DC2626',
                        'HIGH': '#EA580C',
                        'MEDIUM': '#D97706',
                        'LOW': '#2563EB',
                        'INFO': '#6B7280'
                    }
                    color = color_map.get(severity, '#6B7280')
                    
                    elements.append(Paragraph(
                        f"<b>{i}.</b> <font color='{color}'>[{severity}]</font> {html.escape(name)}",
                        self.styles['body']
                    ))
                    
                    if template_id:
                        elements.append(Paragraph(
                            f"<font color='#64748B'>Template: {template_id}</font>",
                            self.styles['code']
                        ))
                    
                    # Matcher name - shows which specific header/tech was detected
                    matcher_name = vuln.get('matcher_name', '')
                    if matcher_name:
                        elements.append(Paragraph(
                            f"<font color='#7C3AED'><b>Detected:</b> {html.escape(matcher_name)}</font>",
                            self.styles['code']
                        ))
                    
                    matched = vuln.get('matched_at', '')
                    if matched:
                        elements.append(Paragraph(
                            f"<font color='#64748B'>Found at: {html.escape(matched)}</font>",
                            self.styles['code']
                        ))
                    
                    # Extracted results - shows detected values (versions, headers, etc.)
                    extracted = vuln.get('extracted_results', [])
                    if extracted:
                        extracted_str = ', '.join(str(e) for e in extracted)
                        elements.append(Paragraph(
                            f"<font color='#059669'><b>Extracted:</b> {html.escape(extracted_str)}</font>",
                            self.styles['code']
                        ))
                    
                    # Tags - useful for categorization (tech, header, cve, etc.)
                    tags = vuln.get('tags', [])
                    if tags:
                        tags_str = ', '.join(tags)
                        elements.append(Paragraph(
                            f"<font color='#64748B'>Tags: {html.escape(tags_str)}</font>",
                            self.styles['code']
                        ))
                    
                    # Description if available
                    desc = vuln.get('description', '')
                    if desc:
                        elements.append(Paragraph(
                            f"<i>{html.escape(desc)}</i>",
                            self.styles['body_small']
                        ))
                    
                    # References if available - show all references
                    references = vuln.get('references', [])
                    if references:
                        for ref in references:
                            elements.append(Paragraph(
                                f"<font color='#0284C7'>Ref: {html.escape(ref)}</font>",
                                self.styles['code']
                            ))
                    
                    elements.append(Spacer(1, 8))
            else:
                elements.append(Paragraph("No vulnerabilities found", self.styles['body']))

        return elements

    def _create_validation_section(self) -> List:
        elements = self._create_section_divider("HTML Validation")
        
        w3c = self.results.get('w3c_validator', {})
        
        if w3c.get('error'):
            elements.append(Paragraph(
                f"Error: {w3c['error']}",
                self.styles['body']
            ))
            return elements
        
        summary = w3c.get('summary', {})
        errors = w3c.get('errors', [])
        warnings = w3c.get('warnings', [])
        
        # Summary
        elements.append(Paragraph(
            f"<b>Errors: {summary.get('errors', 0)}</b> &nbsp;|&nbsp; "
            f"<b>Warnings: {summary.get('warnings', 0)}</b>",
            self.styles['body']
        ))
        elements.append(Spacer(1, 10))
        
        # Errors
        if errors:
            elements.append(Paragraph("<b>Errors</b>", self.styles['subsection']))
            for error in errors:
                msg = html.escape(error.get('message', 'Unknown'))
                line = error.get('lastLine', '?')
                elements.append(Paragraph(
                    f"Line {line}: {msg}",
                    self.styles['body_small']
                ))
        
        # Warnings
        if warnings:
            elements.append(Paragraph("<b>Warnings</b>", self.styles['subsection']))
            for warning in warnings:
                msg = html.escape(warning.get('message', 'Unknown'))
                line = warning.get('lastLine', '?')
                elements.append(Paragraph(
                    f"Line {line}: {msg}",
                    self.styles['body_small']
                ))
        
        if not errors and not warnings:
            elements.append(Paragraph("No HTML validation issues found", self.styles['body']))

        return elements

    def _create_seo_section(self) -> List:
        elements = self._create_section_divider("SEO & Infrastructure")

        if self._has_results('robots_sitemap'):
            rs = self.results['robots_sitemap']
            
            elements.append(Paragraph("<b>SEO Files</b>", self.styles['subsection']))
            
            # Robots.txt
            robots = rs.get('robots_txt', {})
            if robots.get('exists'):
                elements.append(Paragraph("<b>robots.txt</b> found", self.styles['body']))
                if robots.get('has_sitemap_reference'):
                    elements.append(Paragraph("   ↳ References sitemap", self.styles['body_small']))
                if robots.get('has_disallow_rules'):
                    elements.append(Paragraph("   ↳ Contains disallow rules", self.styles['body_small']))
            else:
                elements.append(Paragraph("<b>robots.txt</b> not found", self.styles['body']))
            
            # Sitemap
            sitemap = rs.get('sitemap', {})
            if sitemap.get('exists'):
                url_count = sitemap.get('url_count', 0)
                elements.append(Paragraph(f"<b>sitemap.xml</b> found ({url_count} URLs)", self.styles['body']))
                if not sitemap.get('is_valid_xml'):
                    elements.append(Paragraph("   Invalid XML format", self.styles['body_small']))
            else:
                elements.append(Paragraph("<b>sitemap.xml</b> not found", self.styles['body']))
            
            elements.append(Spacer(1, 15))
        
        # DNS Records
        if self._has_results('dns'):
            dns_data = self.results['dns']
            
            elements.append(Paragraph("<b>DNS Configuration</b>", self.styles['subsection']))
            elements.append(Paragraph(
                f"Hostname: <b>{dns_data.get('hostname', 'N/A')}</b>",
                self.styles['body']
            ))
            
            records = dns_data.get('records', {})
            
            # Show key records
            key_records = ['A', 'AAAA', 'MX', 'NS']
            for record_type in key_records:
                values = records.get(record_type, [])
                if values:
                    elements.append(Paragraph(
                        f"<b>{record_type}:</b> {', '.join(values)}",
                        self.styles['body_small']
                    ))
            
            elements.append(Spacer(1, 8))
            
            # Security features
            if dns_data.get('has_caa'):
                elements.append(Paragraph("CAA records configured", self.styles['body']))
            else:
                elements.append(Paragraph("No CAA records (Certificate Authority Authorization)", self.styles['body_small']))
            
            if dns_data.get('dnssec_enabled'):
                elements.append(Paragraph("DNSSEC enabled", self.styles['body']))
            else:
                elements.append(Paragraph("DNSSEC not detected", self.styles['body_small']))
        
        return elements


class WebsiteTester:

    def __init__(
        self, 
        url: str, 
        max_workers: int = 5, 
        output_directory: str = '/output',
        enable_zap: bool = False, 
        enable_nuclei: bool = False
    ):
        self.url = url
        self.max_workers = max_workers
        self.output_directory = output_directory
        self.enable_zap = enable_zap
        self.enable_nuclei = enable_nuclei
        
        # Ensure output directory exists
        os.makedirs(self.output_directory, exist_ok=True)
        
        # Initialize results structure
        self.results: Dict[str, Any] = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'lighthouse': {},
            'pa11y': {},
            'security_headers': {},
            'ssl': {},
            'owasp_zap': {},
            'nuclei': {},
            'w3c_validator': {},
            'robots_sitemap': {},
            'dns': {}
        }
        
        # Track completed tests
        self.completed_tests: set = set()

    def _get_hostname(self) -> str:
        parsed = urlparse(self.url)
        hostname = parsed.netloc.split(':')[0]
        if not hostname:
            raise ValueError("Invalid URL: missing hostname")
        return hostname

    def _get_host(self) -> str:
        parsed = urlparse(self.url)
        if not parsed.netloc:
            raise ValueError("Invalid URL: missing host")
        return parsed.netloc

    def _get_base_url(self) -> str:
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def run_all_tests(self) -> Dict[str, Any]:
        print(f"\n{'='*70}")
        print(f"  COMPREHENSIVE WEBSITE TESTING")
        print(f"  Target: {self.url}")
        print(f"{'='*70}\n")
        
        security_scans_enabled = self.enable_zap or self.enable_nuclei
        
        print("Phase 1: Running standard tests...")
        standard_tests = [
            ('Security Headers', self._test_security_headers),
            ('DNS Records', self._test_dns),
            ('Robots & Sitemap', self._test_robots_sitemap),
            ('W3C Validation', self._test_w3c),
            ('SSL/TLS Analysis', self._test_ssl),
            ('Accessibility (Pa11y)', self._test_pa11y),
        ]
        
        self._run_tests_parallel(standard_tests)
        
        # Phase 2: Security scans (isolated - these can slow down the website)
        if security_scans_enabled:
            print("\nPhase 2: Running security scans (isolated)...")
            print("   Note: These tests may affect website performance temporarily")

            security_tests = []
            if self.enable_nuclei:
                security_tests.append(('Nuclei Scanner', self._test_nuclei))
            if self.enable_zap:
                security_tests.append(('OWASP ZAP', self._test_owasp_zap))
            self._run_tests_parallel(security_tests)

            print("\n⏳ Waiting for website performance to stabilize...")
            import time
            time.sleep(2)  # Brief pause to let website recover
        else:
            print("\nPhase 2: Security scans skipped (use --enable-zap or --enable-nuclei to enable)")

        print("\nPhase 3: Running Lighthouse performance analysis...")
        self._test_lighthouse()
        print(f"   Lighthouse completed")
        
        print(f"\n{'='*70}")
        print(f"  All tests completed!")
        print(f"{'='*70}\n")
        
        return self.results

    def _run_tests_parallel(self, tests: List[Tuple[str, Callable]]):
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(func): name for name, func in tests}

            for future in as_completed(futures):
                test_name = futures[future]
                try:
                    future.result()
                    print(f"   {test_name}")
                    self.completed_tests.add(test_name)
                except Exception as e:
                    print(f"   {test_name}: {e}")

    def _test_lighthouse(self):
        html_file = os.path.join(self.output_directory, 'lighthouse_report.html')
        
        try:
            cmd = [
                'lighthouse', self.url,
                '--output=html',
                f'--output-path={html_file}',
                '--chrome-flags="--headless --no-sandbox --disable-gpu"',
                '--quiet'
            ]
            
            result = subprocess.run(
                ' '.join(cmd),
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and os.path.exists(html_file):
                self.results['lighthouse'] = {
                    'success': True,
                    'html_report': 'lighthouse_report.html',
                    'full_path': html_file
                }
            else:
                error = result.stderr if result.stderr else 'Unknown error'
                self.results['lighthouse'] = {'error': error, 'success': False}
                
        except FileNotFoundError:
            self.results['lighthouse'] = {'error': 'Lighthouse not installed'}
        except subprocess.TimeoutExpired:
            self.results['lighthouse'] = {'error': 'Timeout after 300s'}
        except Exception as e:
            self.results['lighthouse'] = {'error': str(e)}

    def _test_pa11y(self):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                config = {
                    "chromeLaunchConfig": {
                        "executablePath": "/usr/bin/chromium",
                        "args": ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
                    }
                }
                json.dump(config, f)
                config_file = f.name
            
            try:
                cmd = ['pa11y', self.url, '--runner', 'axe', '--config', config_file, '--reporter', 'json']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                
                output = result.stdout.strip()
                if not output:
                    self.results['pa11y'] = {'error': result.stderr if result.stderr else 'No output'}
                    return
                
                issues = json.loads(output)
                
                # Ensure issues is a list
                if not isinstance(issues, list):
                    issues = []
                
                # Categorize issues
                errors = [i for i in issues if i.get('type') == 'error']
                warnings = [i for i in issues if i.get('type') == 'warning']
                notices = [i for i in issues if i.get('type') == 'notice']
                
                self.results['pa11y'] = {
                    'total_issues': len(issues),
                    'issues': [
                        {
                            'code': issue.get('code', ''),
                            'type': issue.get('type', 'unknown'),
                            'message': issue.get('message', ''),
                            'context': issue.get('context', ''),
                            'selector': issue.get('selector', ''),
                        }
                        for issue in issues
                    ],
                    'summary': {
                        'errors': len(errors),
                        'warnings': len(warnings),
                        'notices': len(notices)
                    }
                }
                
            finally:
                if os.path.exists(config_file):
                    os.unlink(config_file)
                    
        except FileNotFoundError:
            self.results['pa11y'] = {'error': 'Pa11y not installed'}
        except subprocess.TimeoutExpired:
            self.results['pa11y'] = {'error': 'Timeout after 180s'}
        except json.JSONDecodeError as e:
            self.results['pa11y'] = {'error': f'JSON parse error: {e}'}
        except Exception as e:
            self.results['pa11y'] = {'error': str(e)}

    def _test_security_headers(self):
        try:
            host = self._get_host()
            api_url = "https://observatory-api.mdn.mozilla.net/api/v2/scan"
            response = requests.post(api_url, params={'host': host}, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if data and 'grade' in data:
                result = {
                    'grade': data.get('grade'),
                    'score': data.get('score'),
                    'tests_passed': data.get('tests_passed'),
                    'tests_failed': data.get('tests_failed'),
                    'tests_quantity': data.get('tests_quantity'),
                    'report_url': data.get('details_url', 
                        f"https://developer.mozilla.org/en-US/observatory/analyze?host={host}")
                }
            else:
                result = {'error': 'Invalid Observatory response'}
                self.results['security_headers'] = result
                return
            
            # Manual header check
            try:
                resp = requests.get(self.url, timeout=30, verify=True)
                headers = resp.headers
                
                header_checks = {
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
                    'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
                    'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
                    'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
                    'Permissions-Policy': headers.get('Permissions-Policy', 'Missing'),
                }
                
                result['headers'] = header_checks
                result['missing_headers'] = [k for k, v in header_checks.items() if v == 'Missing']
                result['present_headers'] = [k for k, v in header_checks.items() if v != 'Missing']
                
            except requests.RequestException:
                pass  # Observatory data is still useful
            
            self.results['security_headers'] = result
            
        except requests.RequestException as e:
            self.results['security_headers'] = {'error': f'Request failed: {e}'}
        except Exception as e:
            self.results['security_headers'] = {'error': str(e)}

    def _test_ssl(self):
        try:
            hostname = self._get_hostname()
            
            result = subprocess.run(
                ['sslyze', '--json_out=-', hostname],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                self.results['ssl'] = {'error': result.stderr or 'sslyze failed'}
                return
            
            data = json.loads(result.stdout)
            
            # Navigate to server scan results
            server_results = data.get('server_scan_results', [])
            if not server_results:
                self.results['ssl'] = {'error': 'No scan results'}
                return
            
            scan = server_results[0]
            scan_results = scan.get('scan_result', scan.get('scan_commands_results', {}))
            
            # Certificate info
            cert_valid = False
            cert_details = {}
            
            cert_info = scan_results.get('certificate_info', {})
            if cert_info:
                result_data = cert_info.get('result', {})
                deployments = result_data.get('certificate_deployments', [])
                if deployments:
                    deployment = deployments[0]
                    cert_valid = deployment.get('verified_certificate_chain') is not None
                    
                    chain = deployment.get('received_certificate_chain', [])
                    if chain:
                        leaf = chain[0]
                        cert_details = {
                            'subject': str(leaf.get('subject', 'N/A')),
                            'issuer': str(leaf.get('issuer', 'N/A')),
                            'not_valid_before': str(leaf.get('not_valid_before', 'N/A')),
                            'not_valid_after': str(leaf.get('not_valid_after', 'N/A')),
                        }
            
            # TLS versions
            tls_versions = {}
            weak_protocols = []
            has_weak_ciphers = False
            
            for version in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1', 'tls_1_2', 'tls_1_3']:
                version_result = scan_results.get(f'{version}_cipher_suites', {})
                result_data = version_result.get('result', {})
                accepted = result_data.get('accepted_cipher_suites', [])
                
                is_enabled = len(accepted) > 0
                tls_versions[version] = is_enabled
                
                if is_enabled and version in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1']:
                    weak_protocols.append(version.replace('_', '.').upper())
                
                for suite in accepted:
                    name = suite.get('cipher_suite', {}).get('name', '')
                    if any(weak in name for weak in ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']):
                        has_weak_ciphers = True
            
            self.results['ssl'] = {
                'certificate_valid': cert_valid,
                'certificate_details': cert_details,
                'tls_versions_enabled': tls_versions,
                'has_weak_ciphers': has_weak_ciphers,
                'weak_protocols': weak_protocols,
                'supports_tls_1_3': tls_versions.get('tls_1_3', False),
                'supports_tls_1_2': tls_versions.get('tls_1_2', False),
            }
            
        except FileNotFoundError:
            self.results['ssl'] = {'error': 'sslyze not installed'}
        except subprocess.TimeoutExpired:
            self.results['ssl'] = {'error': 'Timeout after 120s'}
        except json.JSONDecodeError:
            self.results['ssl'] = {'error': 'Failed to parse sslyze output'}
        except Exception as e:
            self.results['ssl'] = {'error': str(e)}

    def _test_owasp_zap(self):
        try:
            docker_check = subprocess.run(
                ['docker', '--version'], capture_output=True, timeout=5
            )
            if docker_check.returncode != 0:
                self.results['owasp_zap'] = {'error': 'Docker not available'}
                return
            
            # Ensure ZAP image exists
            image_check = subprocess.run(
                ['docker', 'image', 'inspect', 'zaproxy/zap-stable'],
                capture_output=True, timeout=10
            )
            if image_check.returncode != 0:
                print("      Pulling ZAP image...")
                pull = subprocess.run(
                    ['docker', 'pull', 'zaproxy/zap-stable'],
                    capture_output=True, timeout=300
                )
                if pull.returncode != 0:
                    self.results['owasp_zap'] = {'error': 'Failed to pull ZAP image'}
                    return
            
            # Determine host path for volume mount
            json_file = os.path.join(self.output_directory, 'zap_report.json')
            host_path = self._get_docker_host_path()
            
            try:
                cmd = [
                    'docker', 'run', '--rm',
                    '-v', f'{host_path}:/zap/wrk/:rw',
                    'zaproxy/zap-stable',
                    'zap-baseline.py',
                    '-t', self.url,
                    '-I', '--autooff',
                    '-J', '/zap/wrk/zap_report.json'
                ]
                
                subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if not os.path.exists(json_file):
                    self.results['owasp_zap'] = {'error': 'ZAP report not generated'}
                    return
                
                with open(json_file, 'r') as f:
                    zap_data = json.load(f)
                
                # Parse alerts
                alerts = self._parse_zap_alerts(zap_data)
                
                high = len([a for a in alerts if a.get('risk') in ['High', 'Critical']])
                medium = len([a for a in alerts if a.get('risk') == 'Medium'])
                low = len([a for a in alerts if a.get('risk') == 'Low'])
                info = len([a for a in alerts if a.get('risk') == 'Informational'])
                
                self.results['owasp_zap'] = {
                    'total_alerts': len(alerts),
                    'alerts': alerts,
                    'summary': {'high': high, 'medium': medium, 'low': low, 'info': info}
                }
                
            finally:
                if os.path.exists(json_file):
                    os.remove(json_file)
                    
        except FileNotFoundError:
            self.results['owasp_zap'] = {'error': 'Docker not found'}
        except subprocess.TimeoutExpired:
            self.results['owasp_zap'] = {'error': 'Timeout after 300s'}
        except Exception as e:
            self.results['owasp_zap'] = {'error': str(e)}

    def _parse_zap_alerts(self, zap_data: Dict) -> List[Dict]:
        alerts = []
        
        try:
            sites = zap_data.get('site', [])
            if sites and isinstance(sites, list):
                site_alerts = sites[0].get('alerts', [])
                
                risk_map = {0: 'Informational', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
                confidence_map = {0: 'False Positive', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Confirmed'}
                
                for alert in site_alerts:
                    if not isinstance(alert, dict):
                        continue
                    
                    risk_code = alert.get('riskcode', alert.get('risk', 0))
                    if isinstance(risk_code, str):
                        try:
                            risk_code = int(risk_code)
                        except ValueError:
                            risk_code = 0
                    
                    confidence_code = alert.get('confidence', 0)
                    if isinstance(confidence_code, str):
                        try:
                            confidence_code = int(confidence_code)
                        except ValueError:
                            confidence_code = 0
                    
                    instances = alert.get('instances', [])
                    
                    # Extract URLs from instances
                    urls = []
                    for inst in instances:
                        if isinstance(inst, dict):
                            uri = inst.get('uri', '')
                            if uri:
                                urls.append(uri)
                    
                    alerts.append({
                        'name': alert.get('name', 'Unknown'),
                        'id': str(alert.get('pluginid', '')),
                        'risk': risk_map.get(risk_code, 'Unknown'),
                        'confidence': confidence_map.get(confidence_code, 'Unknown'),
                        'count': len(instances) if instances else 0,
                        'description': alert.get('desc', ''),
                        'solution': alert.get('solution', ''),
                        'reference': alert.get('reference', ''),
                        'cweid': alert.get('cweid', ''),
                        'wascid': alert.get('wascid', ''),
                        'urls': urls,
                    })
        except Exception:
            pass
        
        return alerts

    def _get_docker_host_path(self) -> str:
        try:
            container_id = os.environ.get('HOSTNAME', '')
            if container_id:
                result = subprocess.run(
                    ['docker', 'inspect', '--format', '{{json .Mounts}}', container_id],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    mounts = json.loads(result.stdout)
                    for mount in mounts:
                        if mount.get('Destination') == self.output_directory:
                            return mount.get('Source', self.output_directory)
        except Exception:
            pass
        
        return self.output_directory

    def _test_nuclei(self):
        try:
            result = subprocess.run(
                ['nuclei', '-u', self.url, '-jsonl', '-silent'],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            vulnerabilities = []
            
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            vuln = json.loads(line)
                            info = vuln.get('info', {})
                            classification = info.get('classification', {})
                            
                            vulnerabilities.append({
                                'template_id': vuln.get('template-id'),
                                'name': info.get('name'),
                                'severity': info.get('severity', 'unknown'),
                                'type': vuln.get('type'),
                                'description': info.get('description'),
                                'host': vuln.get('host'),
                                'matched_at': vuln.get('matched-at'),
                                'extracted_results': vuln.get('extracted-results', []),
                                'matcher_name': vuln.get('matcher-name'),
                                'curl_command': vuln.get('curl-command'),
                                'classification': {
                                    'cvss_score': classification.get('cvss-score'),
                                    'cwe_id': classification.get('cwe-id'),
                                },
                                'tags': info.get('tags', []),
                                'references': info.get('reference', []),
                            })
                        except json.JSONDecodeError:
                            continue
            
            # Count by severity
            summary = {
                'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
                'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                'low': len([v for v in vulnerabilities if v.get('severity') == 'low']),
                'info': len([v for v in vulnerabilities if v.get('severity') == 'info']),
                'unknown': len([v for v in vulnerabilities if v.get('severity') == 'unknown']),
            }
            
            self.results['nuclei'] = {
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerabilities': vulnerabilities,
                'summary': summary
            }
            
        except FileNotFoundError:
            self.results['nuclei'] = {'error': 'Nuclei not installed'}
        except subprocess.TimeoutExpired:
            self.results['nuclei'] = {'error': 'Timeout after 600s'}
        except Exception as e:
            self.results['nuclei'] = {'error': str(e)}

    def _test_w3c(self):
        try:
            api_url = f"https://validator.w3.org/nu/?doc={self.url}&out=json"
            
            response = requests.get(
                api_url,
                timeout=60,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; WebsiteTester/1.0)'}
            )
            response.raise_for_status()
            data = response.json()
            
            messages = data.get('messages', [])
            errors = [m for m in messages if m.get('type') == 'error']
            warnings = [m for m in messages if m.get('type') == 'info' or m.get('subType') == 'warning']
            
            self.results['w3c_validator'] = {
                'total_issues': len(messages),
                'errors': errors,
                'warnings': warnings,
                'summary': {
                    'errors': len(errors),
                    'warnings': len(warnings)
                }
            }
            
        except requests.RequestException as e:
            self.results['w3c_validator'] = {'error': f'Request failed: {e}'}
        except Exception as e:
            self.results['w3c_validator'] = {'error': str(e)}

    def _test_robots_sitemap(self):
        base_url = self._get_base_url()
        result = {'robots_txt': {}, 'sitemap': {}}
        try:
            resp = requests.get(f"{base_url}/robots.txt", timeout=30)
            if resp.status_code == 200:
                content = resp.text
                result['robots_txt'] = {
                    'exists': True,
                    'size': len(content),
                    'has_sitemap_reference': 'sitemap' in content.lower(),
                    'has_disallow_rules': 'disallow' in content.lower(),
                }
            else:
                result['robots_txt'] = {'exists': False, 'status_code': resp.status_code}
        except Exception as e:
            result['robots_txt'] = {'error': str(e)}
        
        # Check sitemap.xml
        try:
            resp = requests.get(f"{base_url}/sitemap.xml", timeout=30)
            if resp.status_code == 200:
                content = resp.text
                result['sitemap'] = {
                    'exists': True,
                    'size': len(content),
                    'url_count': content.lower().count('<url>'),
                    'is_valid_xml': content.strip().startswith('<?xml') or content.strip().startswith('<urlset'),
                }
            else:
                result['sitemap'] = {'exists': False, 'status_code': resp.status_code}
        except Exception as e:
            result['sitemap'] = {'error': str(e)}
        
        self.results['robots_sitemap'] = result

    def _test_dns(self):
        try:
            hostname = self._get_hostname()
            records = {}
            for record_type in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    records[record_type] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    records[record_type] = []
                except Exception:
                    records[record_type] = []
            
            # Check CAA
            has_caa = False
            try:
                answers = dns.resolver.resolve(hostname, 'CAA')
                records['CAA'] = [str(r) for r in answers]
                has_caa = True
            except Exception:
                records['CAA'] = []
            
            # Check DNSSEC
            dnssec_enabled = False
            try:
                dns.resolver.resolve(hostname, 'DNSKEY')
                dnssec_enabled = True
            except Exception:
                pass
            
            self.results['dns'] = {
                'hostname': hostname,
                'records': records,
                'has_caa': has_caa,
                'dnssec_enabled': dnssec_enabled
            }
            
        except Exception as e:
            self.results['dns'] = {'error': str(e)}

    def generate_pdf_report(self, output_file: str = 'report.pdf'):
        report_path = os.path.join(self.output_directory, output_file)
        generator = PDFReportGenerator(self.results, report_path)
        generator.generate()


def main():
    parser = argparse.ArgumentParser(
        description='Comprehensive Website Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tester.py https://example.com
  python tester.py https://example.com -o ./reports
  python tester.py https://example.com --enable-zap --enable-nuclei

Standard Tests (always run):
  - Lighthouse (Performance, SEO, Accessibility, Best Practices)
  - Pa11y (Accessibility - WCAG compliance)
  - Security Headers (Mozilla Observatory)
  - SSL/TLS Testing (sslyze)
  - W3C HTML Validator
  - Robots.txt & Sitemap Check
  - DNS Records Analysis

Optional Security Scans (isolated execution):
  - OWASP ZAP - use --enable-zap
  - Nuclei - use --enable-nuclei

Note: Security scans run in isolation to prevent interference with 
Lighthouse performance measurements.
        """
    )
    
    parser.add_argument('url', help='Website URL to test')
    parser.add_argument('-o', '--output', default='/output',
                        help='Output directory for reports (default: /output)')
    parser.add_argument('-j', '--json', help='Save JSON results to file')
    parser.add_argument('-w', '--workers', type=int, default=5,
                        help='Number of parallel workers (default: 5)')
    parser.add_argument('--enable-zap', action='store_true',
                        help='Enable OWASP ZAP security scan')
    parser.add_argument('--enable-nuclei', action='store_true',
                        help='Enable Nuclei vulnerability scanner')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    tester = WebsiteTester(
        url=args.url,
        max_workers=args.workers,
        output_directory=args.output,
        enable_zap=args.enable_zap,
        enable_nuclei=args.enable_nuclei
    )
    
    results = tester.run_all_tests()
    
    if args.json:
        json_path = args.json
        os.makedirs(os.path.dirname(json_path) or '.', exist_ok=True)
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON results saved: {json_path}")

    tester.generate_pdf_report('report.pdf')

    print(f"\nReports saved to: {args.output}/")
    print(f"   - report.pdf - Comprehensive analysis report")
    if results.get('lighthouse', {}).get('success'):
        print(f"   - lighthouse_report.html - Detailed performance analysis")
    print()


if __name__ == '__main__':
    main()
