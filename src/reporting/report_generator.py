"""
Report Generator - Generates periodic reports of security threats
"""

import asyncio
import datetime
import json
import logging
import os
import time
from pathlib import Path
import re
from typing import Dict, Any, List, Optional


class ReportGenerator:
    """Generate reports of security threats based on configured schedule"""
    
    def __init__(self, settings, database):
        self.settings = settings
        self.database = database
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.scheduler_task = None
        self.last_report_time = 0
        self.min_report_interval = 300  # Minimum 5 minutes between reports
    
    async def start_scheduler(self):
        """Start the report scheduler"""
        self.logger.info("Starting report scheduler...")
        self.running = True
        
        # Schedule based on configured interval
        interval_seconds = self._get_schedule_interval()
        
        # Initial report on startup (forced)
        await self.generate_report(force=True)
        
        # Schedule periodic reports
        while self.running:
            try:
                await asyncio.sleep(interval_seconds)
                if self.running:  # Check again after sleep
                    # Non-forced, will respect the minimum interval
                    await self.generate_report()
            except asyncio.CancelledError:
                self.logger.info("Report scheduler task cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in report scheduler: {e}")
                await asyncio.sleep(60)  # Wait a minute and try again
    
    async def stop(self):
        """Stop the report scheduler"""
        self.logger.info("Stopping report scheduler...")
        self.running = False
        
        if self.scheduler_task and not self.scheduler_task.done():
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
    
    def _get_schedule_interval(self) -> int:
        """Get the schedule interval in seconds"""
        schedule = self.settings.report_schedule.lower()
        
        if schedule == 'hourly':
            return 60 * 60
        elif schedule == 'daily':
            return 24 * 60 * 60
        elif schedule == 'weekly':
            return 7 * 24 * 60 * 60
        else:
            # Default to daily
            self.logger.warning(f"Unknown schedule '{schedule}', defaulting to daily")
            return 24 * 60 * 60
    
    async def generate_report(self, 
                            time_range: Optional[int] = None, 
                            force: bool = False) -> List[str]: # Return list of paths
        """Generate a report of security threats"""
        current_time = time.time()
        
        # Check if we've generated a report recently (to prevent duplicates)
        if not force and (current_time - self.last_report_time) < self.min_report_interval:
            self.logger.info(f"Skipping report generation - last report was generated {int(current_time - self.last_report_time)} seconds ago")
            return [] # Return empty list if skipped
            
        self.logger.info("Generating security threat report...")
        
        try:
            # Determine time range
            if time_range is None:
                schedule = self.settings.report_schedule.lower()
                if schedule == 'hourly':
                    time_range = 60 * 60  # 1 hour in seconds
                elif schedule == 'daily':
                    time_range = 24 * 60 * 60  # 1 day in seconds
                elif schedule == 'weekly':
                    time_range = 7 * 24 * 60 * 60  # 1 week in seconds
                else:
                    time_range = 24 * 60 * 60  # Default to daily
            
            # Calculate time range
            end_time = datetime.datetime.now().timestamp()
            start_time = end_time - time_range
            
            self.logger.debug(f"Retrieving threats from {datetime.datetime.fromtimestamp(start_time)} to {datetime.datetime.fromtimestamp(end_time)}")
            
            # Get threats from database
            threats = await self.database.get_threats(
                limit=1000,  # Reasonable limit for a report
                start_time=start_time,
                end_time=end_time
            )
            
            # Check if there are any threats to report on
            # Skip report generation if there are no threats and this is not a forced report
            if not threats and not force:
                self.logger.info("No threats found for this time period. Skipping report generation.")
                return [] # Return empty list if skipped
                
            # If it's a forced report and there are no threats, log a warning
            if not threats and force:
                self.logger.warning("Generating a report with no threats because force=True")
            
            generated_report_paths = []
            report_formats = getattr(self.settings, 'report_formats', ['html']) # Default to HTML if not set
            
            for output_format in report_formats:
                report_content = ""
                file_ext = ""
                if output_format.lower() == 'json':
                    report_content = self._generate_json_report(threats, start_time, end_time)
                    file_ext = 'json'
                elif output_format.lower() == 'html':
                    report_content = self._generate_html_report(threats, start_time, end_time)
                    file_ext = 'html'
                else:
                    self.logger.warning(f"Unsupported report format: {output_format}. Skipping.")
                    continue

                # Log threat count for debugging
                self.logger.info(f"Found {len(threats)} threats for report ({output_format} format)")
                if threats:
                    for idx, threat in enumerate(threats):
                        self.logger.debug(f"Threat {idx+1}: {threat.get('summary', 'No summary')} - {threat.get('severity', 'UNKNOWN')}")
                
                # Save the report
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                report_filename = f"security_report_{timestamp}.{file_ext}"
                report_path = os.path.join(self.settings.output_log_dir, report_filename)
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(report_path), exist_ok=True)
                
                # Write report to file
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                
                self.logger.info(f"Report generated successfully: {report_path}")
                generated_report_paths.append(report_path)
                
                # Create 'latest' symlink or copy for the current format
                latest_path = os.path.join(self.settings.output_log_dir, f"latest_report.{file_ext}")
                try:
                    if os.path.exists(latest_path):
                        os.remove(latest_path)
                    report_filename_relative = os.path.basename(report_path)
                    os.symlink(report_filename_relative, latest_path)
                    self.logger.info(f"Created symlink: {latest_path} -> {report_filename_relative}")
                except OSError as e:
                    self.logger.warning(f"Could not create symlink for {file_ext} report, creating copy instead: {e}")
                    with open(latest_path, 'w', encoding='utf-8') as f:
                        f.write(report_content)
            
            # Update last report time only if at least one report was generated
            if generated_report_paths:
                self.last_report_time = time.time()
                await self._update_reports_json() # Update reports.json after all formats are generated

            return generated_report_paths
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return []
    
    def _generate_json_report(self, threats: List[Dict[str, Any]], start_time: float, end_time: float) -> str:
        """Generate a JSON report"""
        report_data = {
            "report_generated_at": datetime.datetime.now().isoformat(),
            "report_period": {
                "start": datetime.datetime.fromtimestamp(start_time).isoformat(),
                "end": datetime.datetime.fromtimestamp(end_time).isoformat()
            },
            "threats_count": {
                "total": len(threats),
                "by_severity": self._count_by_severity(threats)
            },
            "threats": threats
        }
        
        return json.dumps(report_data, indent=2)
    
    def _generate_html_report(self, threats: List[Dict[str, Any]], start_time: float, end_time: float) -> str:
        """Generate an HTML report with modern styling matching the dashboard"""
        start_time_str = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        end_time_str = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')
        
        severity_counts = self._count_by_severity(threats)
        
        # Build HTML content with modern styling
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Logger - Security Threat Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {{
            --primary-color: #667eea;
            --primary-dark: #5a67d8;
            --secondary-color: #764ba2;
            --accent-color: #f093fb;
            --success-color: #48bb78;
            --warning-color: #ed8936;
            --error-color: #f56565;
            --info-color: #4299e1;
            --critical-color: #e53e3e;
            --background-color: #f7fafc;
            --surface-color: #ffffff;
            --text-primary: #2d3748;
            --text-secondary: #718096;
            --border-color: #e2e8f0;
            --shadow-light: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.06);
            --shadow-medium: 0 4px 6px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.06);
            --shadow-large: 0 10px 15px rgba(0, 0, 0, 0.1), 0 4px 6px rgba(0, 0, 0, 0.05);
            --gradient-primary: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            --gradient-accent: linear-gradient(135deg, var(--accent-color) 0%, var(--primary-color) 100%);
        }}

        [data-theme="dark"] {{
            --primary-color: #7c3aed;
            --primary-dark: #6d28d9;
            --secondary-color: #a855f7;
            --accent-color: #ec4899;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --error-color: #ef4444;
            --info-color: #3b82f6;
            --critical-color: #dc2626;
            --background-color: #0f172a;
            --surface-color: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --shadow-light: 0 1px 3px rgba(0, 0, 0, 0.3), 0 1px 2px rgba(0, 0, 0, 0.2);
            --shadow-medium: 0 4px 6px rgba(0, 0, 0, 0.3), 0 2px 4px rgba(0, 0, 0, 0.2);
            --shadow-large: 0 10px 15px rgba(0, 0, 0, 0.4), 0 4px 6px rgba(0, 0, 0, 0.2);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--background-color);
            overflow-x: hidden;
        }}

        .background-pattern {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 25% 25%, rgba(102, 126, 234, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 75% 75%, rgba(118, 75, 162, 0.1) 0%, transparent 50%);
            z-index: -1;
        }}

        .header {{
            background: var(--gradient-primary);
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: var(--shadow-medium);
            position: relative;
            overflow: hidden;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.5;
        }}

        .header-content {{
            position: relative;
            z-index: 1;
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }}

        .header-controls {{
            position: absolute;
            top: 1rem;
            right: 1rem;
            display: flex;
            gap: 1rem;
            z-index: 2;
        }}

        .theme-toggle {{
            background: rgba(255, 255, 255, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.3);
            color: white;
            padding: 0.5rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }}

        .theme-toggle:hover {{
            background: rgba(255, 255, 255, 0.3);
            transform: scale(1.05);
        }}

        .header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}

        .header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
            font-weight: 400;
        }}

        .nav-breadcrumb {{
            background: var(--surface-color);
            padding: 1rem 0;
            border-bottom: 1px solid var(--border-color);
        }}

        .breadcrumb {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-secondary);
        }}

        .breadcrumb a {{
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
        }}

        .breadcrumb a:hover {{
            text-decoration: underline;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem 1rem;
        }}

        .report-summary {{
            background: var(--surface-color);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-medium);
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }}

        .report-summary::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-accent);
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }}

        .summary-item {{
            text-align: center;
        }}

        .summary-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }}

        .summary-value {{
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }}

        .stat-card {{
            background: var(--surface-color);
            padding: 2rem;
            border-radius: 12px;
            text-align: center;
            border: 1px solid var(--border-color);
            transition: all 0.2s ease;
            position: relative;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-medium);
        }}

        .stat-icon {{
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem;
            font-size: 1.5rem;
            color: white;
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 1rem;
            font-weight: 500;
        }}

        .section {{
            background: var(--surface-color);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-medium);
            border: 1px solid var(--border-color);
        }}

        .section-header {{
            display: flex;
            align-items: center;
            margin-bottom: 1.5rem;
        }}

        .section-icon {{
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: var(--gradient-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            color: white;
            font-size: 1.5rem;
        }}

        .section-title {{
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .threat-card {{
            background: var(--background-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: all 0.2s ease;
        }}

        .threat-card:hover {{
            transform: translateY(-2px);
            box-shadow: var(--shadow-medium);
        }}

        .threat-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .threat-info h3 {{
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }}

        .threat-time {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .severity-badge {{
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-CRITICAL {{
            background: var(--critical-color);
            color: white;
        }}

        .severity-ERROR {{
            background: var(--error-color);
            color: white;
        }}

        .severity-WARNING {{
            background: var(--warning-color);
            color: white;
        }}

        .severity-INFO {{
            background: var(--info-color);
            color: white;
        }}

        .threat-details {{
            margin: 1rem 0;
            color: var(--text-primary);
        }}

        .log-entries {{
            background: #1a202c;
            color: #e2e8f0;
            padding: 1.5rem;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.875rem;
            white-space: pre-wrap;
            overflow-x: auto;
            line-height: 1.5;
            border: 1px solid #2d3748;
        }}

        .empty-state {{
            text-align: center;
            padding: 4rem 2rem;
            color: var(--text-secondary);
        }}

        .empty-state i {{
            font-size: 4rem;
            color: var(--success-color);
            margin-bottom: 1rem;
        }}

        .empty-state h3 {{
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }}

        .empty-state p {{
            font-size: 1rem;
            max-width: 400px;
            margin: 0 auto;
        }}

        .footer {{
            margin-top: 4rem;
            text-align: center;
            padding: 2rem 0;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
        }}

        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2rem;
            }}
            
            .container {{
                padding: 1rem;
            }}
            
            .section {{
                padding: 1.5rem;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
                gap: 1rem;
            }}
            
            .summary-grid {{
                grid-template-columns: 1fr;
                gap: 1rem;
            }}
            
            .threat-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
            }}
        }}

        @media print {{
            .header-controls {{
                display: none;
            }}
            
            .section {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="background-pattern"></div>
    
    <header class="header">
        <div class="header-controls">
            <button class="theme-toggle" onclick="toggleTheme()" title="Toggle Dark Mode">
                <i class="fas fa-moon" id="theme-icon"></i>
            </button>
        </div>
        <div class="header-content">
            <h1><i class="fas fa-shield-alt"></i> Security Threat Report</h1>
            <p class="subtitle">Automated Threat Analysis & Detection Results</p>
        </div>
    </header>

    <div class="nav-breadcrumb">
        <div class="breadcrumb">
            <a href="index.html"><i class="fas fa-home"></i> Dashboard</a>
            <i class="fas fa-chevron-right"></i>
            <span>Security Report</span>
        </div>
    </div>

    <div class="container">
        <div class="report-summary">
            <h2><i class="fas fa-chart-line"></i> Report Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-label">Report Period</div>
                    <div class="summary-value">{start_time_str} to {end_time_str}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Generated</div>
                    <div class="summary-value">{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Total Threats</div>
                    <div class="summary-value">{len(threats)}</div>
                </div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon" style="background: var(--critical-color);">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="stat-number">{severity_counts.get('CRITICAL', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon" style="background: var(--error-color);">
                    <i class="fas fa-times-circle"></i>
                </div>
                <div class="stat-number">{severity_counts.get('ERROR', 0)}</div>
                <div class="stat-label">Error</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon" style="background: var(--warning-color);">
                    <i class="fas fa-exclamation-circle"></i>
                </div>
                <div class="stat-number">{severity_counts.get('WARNING', 0)}</div>
                <div class="stat-label">Warning</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon" style="background: var(--info-color);">
                    <i class="fas fa-info-circle"></i>
                </div>
                <div class="stat-number">{severity_counts.get('INFO', 0)}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <div class="section-icon">
                    <i class="fas fa-bug"></i>
                </div>
                <h2 class="section-title">Detected Threats</h2>
            </div>
            
            {self._generate_threats_html(threats) if threats else self._generate_empty_state_html()}
        </div>

        <div class="footer">
            <p><strong>AI Security Logger v2.0</strong> - Powered by Advanced ML Models</p>
            <p>Report generated automatically on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
    </div>

    <script>
        function toggleTheme() {{
            const body = document.body;
            const themeIcon = document.getElementById('theme-icon');
            
            if (body.getAttribute('data-theme') === 'dark') {{
                body.removeAttribute('data-theme');
                themeIcon.className = 'fas fa-moon';
                localStorage.setItem('theme', 'light');
            }} else {{
                body.setAttribute('data-theme', 'dark');
                themeIcon.className = 'fas fa-sun';
                localStorage.setItem('theme', 'dark');
            }}
        }}

        function initializeTheme() {{
            const savedTheme = localStorage.getItem('theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const themeIcon = document.getElementById('theme-icon');
            
            if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {{
                document.body.setAttribute('data-theme', 'dark');
                themeIcon.className = 'fas fa-sun';
            }} else {{
                themeIcon.className = 'fas fa-moon';
            }}
        }}

        document.addEventListener('DOMContentLoaded', function() {{
            initializeTheme();
        }});
    </script>
</body>
</html>
"""
        return html
    
    def _generate_threats_html(self, threats: List[Dict[str, Any]]) -> str:
        """Generate HTML for the threats section using modern card-based design"""            
        threats_html = ""
        
        # Define severity order
        severity_order = {'CRITICAL': 0, 'ERROR': 1, 'WARNING': 2, 'INFO': 3, 'LOW': 4, 'UNKNOWN': 5}
        
        # Sort threats by severity
        sorted_threats = sorted(threats, key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 5))
        
        for threat in sorted_threats: # Iterate over sorted threats
            try:
                severity = threat.get('severity', 'INFO')
                timestamp = datetime.datetime.fromtimestamp(threat.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')
                summary = threat.get('summary', 'Unknown Threat')
                
                # Generate log entries HTML
                log_entries = threat.get('log_entries', [])
                log_entries_html = ""
                
                if log_entries:
                    for entry in log_entries:
                        if isinstance(entry, dict):
                            source = entry.get('source_file', 'unknown')
                            raw_line = entry.get('raw_line', '')
                            log_entries_html += f"[{source}] {raw_line}\\n"
                        else:
                            log_entries_html += f"{str(entry)}\\n"
                else:
                    log_entries_html = "No log entries available"
                
                # Build the threat HTML using modern card design
                threats_html += f"""
            <div class="threat-card">
                <div class="threat-header">
                    <div class="threat-info">
                        <h3>{summary}</h3>
                        <div class="threat-time">
                            <i class="fas fa-clock"></i> {timestamp}
                        </div>
                    </div>
                    <span class="severity-badge severity-{severity}">
                        <i class="fas fa-{'exclamation-triangle' if severity == 'CRITICAL' else 'times-circle' if severity == 'ERROR' else 'exclamation-circle' if severity == 'WARNING' else 'info-circle'}"></i>
                        {severity}
                    </span>
                </div>
                
                <div class="threat-details">
                    <p><strong><i class="fas fa-info-circle"></i> Details:</strong></p>
                    <p>{threat.get('details', 'No details available')}</p>
                    
                    {f'<p><strong><i class="fas fa-lightbulb"></i> Recommended Actions:</strong></p><p>{threat.get("recommended_actions", "")}</p>' if threat.get('recommended_actions') else ''}
                </div>
                
                <details style="margin-top: 1rem;">
                    <summary style="cursor: pointer; font-weight: 600; color: var(--primary-color); padding: 0.5rem 0;">
                        <i class="fas fa-file-alt"></i> View Log Entries
                    </summary>
                    <div class="log-entries">{log_entries_html}</div>
                </details>
            </div>
"""
            except Exception as e:
                self.logger.error(f"Error formatting threat for HTML: {e}")
                threats_html += f"""
            <div class="threat-card">
                <div class="threat-header">
                    <div class="threat-info">
                        <h3>Error Processing Threat</h3>
                        <div class="threat-time">
                            <i class="fas fa-clock"></i> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        </div>
                    </div>
                    <span class="severity-badge severity-WARNING">
                        <i class="fas fa-exclamation-circle"></i>
                        WARNING
                    </span>
                </div>
                <div class="threat-details">
                    <p>There was an error processing this threat data: {str(e)}</p>
                </div>
            </div>
"""
        
        return threats_html
    
    def _generate_empty_state_html(self) -> str:
        """Generate HTML for empty state when no threats are found"""
        return """
            <div class="empty-state">
                <i class="fas fa-shield-check"></i>
                <h3>No Security Threats Detected</h3>
                <p>Excellent! No threats were detected during this reporting period. Your systems appear to be secure.</p>
                <div style="margin-top: 1.5rem; padding: 1rem; background: var(--background-color); border-radius: 8px; border: 1px solid var(--border-color);">
                    <p style="margin-bottom: 0.5rem;"><strong>This could indicate:</strong></p>
                    <ul style="text-align: left; max-width: 400px; margin: 0 auto;">
                        <li>All systems are operating normally</li>
                        <li>Security measures are effectively preventing threats</li>
                        <li>No suspicious activity detected in logs</li>
                    </ul>
                </div>
            </div>
        """
    
    def _count_by_severity(self, threats: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count threats by severity"""
        counts = {}
        
        for threat in threats:
            severity = threat.get('severity', 'UNKNOWN')
            counts[severity] = counts.get(severity, 0) + 1
        
        return counts

    async def _update_reports_json(self):
        """Generate and save a JSON file with a list of all security reports."""
        self.logger.info("Updating reports.json...")
        reports_dir = Path(self.settings.output_log_dir)
        report_files = []

        for f in reports_dir.iterdir():
            if f.is_file() and f.name.startswith("security_report_") and (f.suffix == ".html" or f.suffix == ".json"):
                timestamp_match = re.search(r'(\d{8}_\d{6})', f.name)
                timestamp = timestamp_match.group(1) if timestamp_match else "unknown"
                report_files.append({
                    "name": f.name,
                    "path": f.name,  # Path relative to the reports directory
                    "timestamp": timestamp
                })
        
        # Sort reports by timestamp, newest first
        report_files.sort(key=lambda x: x['timestamp'], reverse=True)

        reports_json_path = reports_dir / "reports.json"
        try:
            with open(reports_json_path, 'w', encoding='utf-8') as f:
                json.dump(report_files, f, indent=2)
            self.logger.info(f"Successfully updated {reports_json_path}")
        except Exception as e:
            self.logger.error(f"Error writing reports.json: {e}")
