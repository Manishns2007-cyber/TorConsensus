"""
PDF Report Generator for TOR-Unveil FTDC Analysis
Generates comprehensive forensic reports with chain-of-custody metadata
"""
import io
import base64
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.colors import HexColor


class ForensicReportGenerator:
    """Generate professional PDF forensic reports for TOR traffic analysis"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Create custom paragraph styles for the report"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=HexColor('#764ba2'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.grey,
            alignment=TA_RIGHT
        ))
    
    def generate_report(self, analysis_result, output_path, case_metadata=None):
        """
        Generate comprehensive PDF forensic report
        
        Args:
            analysis_result: Dictionary containing analysis results
            output_path: Path to save the PDF
            case_metadata: Optional case information (investigator, case_id, etc.)
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Header
        story.append(Paragraph("TOR-Unveil: Forensic Analysis Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 12))
        
        # Chain of Custody
        story.append(Paragraph("Chain of Custody", self.styles['SectionHeader']))
        custody_data = [
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Analysis ID:', analysis_result.get('analysis_id', 'N/A')],
            ['PCAP Filename:', analysis_result.get('pcap_filename', 'N/A')],
            ['Analysis Duration:', f"{analysis_result.get('analysis_duration', 0):.2f}s"],
        ]
        
        if case_metadata:
            custody_data.extend([
                ['Case ID:', case_metadata.get('case_id', 'N/A')],
                ['Investigator:', case_metadata.get('investigator', 'N/A')],
                ['Agency:', case_metadata.get('agency', 'TN Police Cybercrime Division')],
            ])
        
        custody_table = Table(custody_data, colWidths=[2*inch, 4*inch])
        custody_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        story.append(custody_table)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        summary_text = f"""
        This report presents the results of an automated TOR traffic analysis using the Flow Time-Density 
        Correlation (FTDC) method. The analysis identified {len(analysis_result.get('guard_rankings', []))} 
        potential guard nodes with an average confidence of {analysis_result.get('correlation_stats', {}).get('avg_confidence', 0)*100:.1f}%. 
        The system analyzed network traffic patterns to probabilistically correlate TOR entry and exit nodes.
        """
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Analysis Overview
        story.append(Paragraph("Analysis Overview", self.styles['SectionHeader']))
        overview_data = [
            ['Metric', 'Value'],
            ['Total Guard Candidates', str(len(analysis_result.get('guard_rankings', [])))],
            ['Average Confidence Score', f"{analysis_result.get('correlation_stats', {}).get('avg_confidence', 0)*100:.1f}%"],
            ['Improvement Factor', f"{analysis_result.get('improvement_factor', 0):.2f}x"],
            ['Circuit Paths Identified', str(len(analysis_result.get('paths', [])))],
            ['Correlation Trend', analysis_result.get('correlation_stats', {}).get('trend', 'N/A')],
        ]
        
        overview_table = Table(overview_data, colWidths=[3*inch, 3*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(overview_table)
        story.append(Spacer(1, 20))
        
        # Top Guard Nodes
        story.append(Paragraph("Top Guard Node Candidates", self.styles['SectionHeader']))
        guard_data = [['Rank', 'Nickname', 'IP Address', 'Country', 'Confidence', 'Flags']]
        
        for i, guard in enumerate(analysis_result.get('guard_rankings', [])[:10], 1):
            guard_data.append([
                str(i),
                guard.get('nickname', 'N/A')[:15],
                guard.get('ip', 'N/A'),
                guard.get('country', 'N/A'),
                f"{guard.get('confidence', 0)*100:.1f}%",
                ', '.join(guard.get('flags', [])[:3])
            ])
        
        guard_table = Table(guard_data, colWidths=[0.5*inch, 1.2*inch, 1.3*inch, 0.8*inch, 0.9*inch, 1.8*inch])
        guard_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#764ba2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#f9f9f9')])
        ]))
        story.append(guard_table)
        story.append(Spacer(1, 20))
        
        # AI Risk Assessment Section
        ai_risk_assessments = analysis_result.get('ai_risk_assessments', [])
        ai_interpretation = analysis_result.get('ai_interpretation', {})
        
        if ai_risk_assessments:
            story.append(Paragraph("AI Risk Assessment", self.styles['SectionHeader']))
            
            # AI Disclaimer
            ai_disclaimer = """
            <b>⚠️ AI DECISION SUPPORT NOTICE:</b> The following AI-generated risk scores provide 
            <b>investigative prioritization only</b>. These scores indicate statistical patterns worthy of 
            further analysis — they do NOT identify individual users or prove any connection to specific 
            activities. Always cross-reference with additional intelligence sources before drawing conclusions.
            """
            story.append(Paragraph(ai_disclaimer, self.styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Risk Band Summary
            high_risk = sum(1 for a in ai_risk_assessments if a.get('risk_band') == 'HIGH')
            medium_risk = sum(1 for a in ai_risk_assessments if a.get('risk_band') == 'MEDIUM')
            low_risk = sum(1 for a in ai_risk_assessments if a.get('risk_band') == 'LOW')
            
            risk_summary_data = [
                ['Risk Level', 'Count', 'Recommendation'],
                ['HIGH', str(high_risk), 'Immediate Review Recommended'],
                ['MEDIUM', str(medium_risk), 'Further Investigation Warranted'],
                ['LOW', str(low_risk), 'Standard Processing']
            ]
            
            risk_summary_table = Table(risk_summary_data, colWidths=[1.5*inch, 1*inch, 3*inch])
            risk_summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('BACKGROUND', (0, 1), (-1, 1), HexColor('#ffcdd2')),  # High risk - red
                ('BACKGROUND', (0, 2), (-1, 2), HexColor('#ffe082')),  # Medium risk - yellow
                ('BACKGROUND', (0, 3), (-1, 3), HexColor('#c8e6c9')),  # Low risk - green
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(risk_summary_table)
            story.append(Spacer(1, 12))
            
            # AI Interpretation
            if ai_interpretation:
                if ai_interpretation.get('summary'):
                    story.append(Paragraph(f"<b>AI Summary:</b> {ai_interpretation['summary']}", self.styles['Normal']))
                if ai_interpretation.get('high_risk_summary'):
                    story.append(Paragraph(f"<b>High Priority Factors:</b> {ai_interpretation['high_risk_summary']}", self.styles['Normal']))
                story.append(Spacer(1, 12))
            
            # Detailed AI Risk Table
            ai_risk_data = [['Rank', 'Fingerprint', 'Risk Score', 'Risk Band', 'Top Factors']]
            
            for i, assessment in enumerate(ai_risk_assessments[:10], 1):
                factors = assessment.get('top_contributing_factors', [])
                factor_str = ', '.join([f['factor'] for f in factors[:2]]) if factors else 'N/A'
                ai_risk_data.append([
                    str(i),
                    assessment.get('fingerprint', 'N/A')[:12] + '...',
                    f"{assessment.get('risk_score', 0)*100:.1f}%",
                    assessment.get('risk_band', 'N/A'),
                    factor_str[:30]
                ])
            
            ai_risk_table = Table(ai_risk_data, colWidths=[0.5*inch, 1.3*inch, 1*inch, 1*inch, 2.7*inch])
            ai_risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#9c27b0')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, HexColor('#f9f9f9')])
            ]))
            story.append(ai_risk_table)
            story.append(Spacer(1, 20))
        
        # Circuit Paths
        story.append(Paragraph("Identified Circuit Paths", self.styles['SectionHeader']))
        
        for i, path_info in enumerate(analysis_result.get('paths', [])[:5], 1):
            path_nodes = path_info.get('path', [])
            confidence = path_info.get('confidence', 0)
            
            story.append(Paragraph(f"<b>Path {i} (Confidence: {confidence*100:.1f}%)</b>", self.styles['Normal']))
            
            path_data = [['Role', 'Nickname', 'IP', 'Country']]
            roles = ['Guard', 'Middle', 'Exit']
            
            for j, node in enumerate(path_nodes):
                path_data.append([
                    roles[j] if j < len(roles) else 'Unknown',
                    node.get('nickname', 'N/A')[:20],
                    node.get('ip', 'N/A'),
                    node.get('country', 'N/A')
                ])
            
            path_table = Table(path_data, colWidths=[1*inch, 2*inch, 1.5*inch, 1*inch])
            path_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#17a2b8')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(path_table)
            story.append(Spacer(1, 12))
        
        # Methodology
        story.append(PageBreak())
        story.append(Paragraph("Methodology", self.styles['SectionHeader']))
        methodology_text = """
        <b>Flow Time-Density Correlation (FTDC) Analysis</b><br/>
        <br/>
        The analysis employs a multi-factor correlation approach:<br/>
        <br/>
        1. <b>Temporal Correlation:</b> Compares timing patterns between exit node traffic and potential 
        guard node activity using sliding window analysis (50ms default).<br/>
        <br/>
        2. <b>Bandwidth Correlation:</b> Analyzes bandwidth capacity and utilization patterns to identify 
        relays capable of handling observed traffic volumes.<br/>
        <br/>
        3. <b>Circuit Pattern Matching:</b> Uses weighted scoring across three dimensions:
        - Bandwidth Score (50%): Relay capacity vs. required throughput
        - Quality Score (30%): Uptime, flags, and reliability metrics
        - Network Proximity (20%): Geographic and AS-level proximity analysis<br/>
        <br/>
        4. <b>Iterative Improvement:</b> Bayesian-like updating mechanism that refines confidence scores 
        as more correlation data becomes available.<br/>
        <br/>
        <b>Confidence Interpretation:</b><br/>
        - High (>70%): Strong correlation evidence, prioritize for investigation<br/>
        - Medium (40-70%): Moderate correlation, requires additional validation<br/>
        - Low (<40%): Weak correlation, consider as background noise<br/>
        """
        story.append(Paragraph(methodology_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Disclaimers
        story.append(Paragraph("Legal and Technical Disclaimers", self.styles['SectionHeader']))
        disclaimer_text = """
        <b>IMPORTANT:</b> This report contains probabilistic correlation analysis results. The system does NOT:
        - Decrypt TOR traffic or compromise user anonymity through cryptographic attacks
        - Perform active network attacks or exploit vulnerabilities
        - Guarantee 100% accuracy in guard node identification<br/>
        <br/>
        Results should be used as investigative leads requiring additional corroboration through traditional 
        forensic methods. All analysis respects the integrity of the TOR network and is intended solely for 
        lawful cybercrime investigation purposes.<br/>
        <br/>
        <b>Chain of Custody:</b> This report was generated automatically by the TOR-Unveil system. 
        Any manual modifications to this document invalidate its forensic integrity.
        """
        story.append(Paragraph(disclaimer_text, self.styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"TOR-Unveil FTDC Analysis System | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Page 1 of 1"
        story.append(Paragraph(footer_text, self.styles['Metadata']))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    def generate_csv_export(self, guard_rankings, output_path):
        """Export guard rankings to CSV format"""
        import csv
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Rank', 'Nickname', 'Fingerprint', 'IP', 'Country', 'Confidence', 
                           'Bandwidth', 'Uptime', 'Flags', 'AS Number', 'AS Name'])
            
            for i, guard in enumerate(guard_rankings, 1):
                writer.writerow([
                    i,
                    guard.get('nickname', 'N/A'),
                    guard.get('fingerprint', 'N/A'),
                    guard.get('ip', 'N/A'),
                    guard.get('country', 'N/A'),
                    f"{guard.get('confidence', 0):.4f}",
                    guard.get('bandwidth', 0),
                    guard.get('uptime', 0),
                    '|'.join(guard.get('flags', [])),
                    guard.get('as_number', 'N/A'),
                    guard.get('as_name', 'N/A')
                ])
        
        return output_path
    
    def generate_json_export(self, analysis_result, output_path):
        """Export full analysis results to JSON format"""
        import json
        
        # Remove non-serializable visualization HTML
        export_data = analysis_result.copy()
        if 'visualizations' in export_data:
            del export_data['visualizations']
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        return output_path
