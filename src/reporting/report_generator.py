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
                            output_format: str = 'html',
                            force: bool = False) -> str:
        """Generate a report of security threats"""
        current_time = time.time()
        
        # Check if we've generated a report recently (to prevent duplicates)
        if not force and (current_time - self.last_report_time) < self.min_report_interval:
            self.logger.info(f"Skipping report generation - last report was generated {int(current_time - self.last_report_time)} seconds ago")
            return ""
            
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
            
            # Calculate time range - Use a wider range to ensure we catch all threats
            end_time = datetime.datetime.now().timestamp()
            start_time = end_time - (time_range * 3)  # Multiply by 3 to extend the window
            
            self.logger.debug(f"Retrieving threats from {datetime.datetime.fromtimestamp(start_time)} to {datetime.datetime.fromtimestamp(end_time)}")
            
            # Get threats from database
            threats = await self.database.get_threats(
                limit=1000,  # Reasonable limit for a report
                start_time=start_time,
                end_time=end_time
            )
            
            # Generate the report
            if output_format.lower() == 'json':
                report_content = self._generate_json_report(threats, start_time, end_time)
                file_ext = 'json'
            else:
                report_content = self._generate_html_report(threats, start_time, end_time)
                file_ext = 'html'
            
            # Log threat count for debugging
            self.logger.info(f"Found {len(threats)} threats for report")
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
            
            # Update last report time
            self.last_report_time = time.time()
            
            # Create 'latest' symlink or copy
            latest_path = os.path.join(self.settings.output_log_dir, f"latest_report.{file_ext}")
            try:
                if os.path.exists(latest_path):
                    os.remove(latest_path)
                os.symlink(report_path, latest_path)
            except OSError:
                # Symlinks might not be supported, create a copy instead
                with open(latest_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return ""
    
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
        """Generate an HTML report"""
        start_time_str = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        end_time_str = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')
        
        severity_counts = self._count_by_severity(threats)
        
        # Build HTML content
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Threat Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #3498db;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .threat {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .threat-header {{
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 10px;
        }}
        .severity {{
            font-weight: bold;
            padding: 3px 10px;
            border-radius: 3px;
            color: white;
        }}
        .CRITICAL {{
            background-color: #e74c3c;
        }}
        .ERROR {{
            background-color: #e67e22;
        }}
        .WARNING {{
            background-color: #f1c40f;
            color: #333;
        }}
        .INFO {{
            background-color: #3498db;
        }}
        .log-entries {{
            background-color: #f9f9f9;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            margin-top: 10px;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat-box {{
            flex: 1;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 24px;
            font-weight: bold;
        }}
        .empty-message {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <h1>AI Security Logger - Threat Report</h1>
    
    <div class="summary">
        <p><strong>Report Period:</strong> {start_time_str} to {end_time_str}</p>
        <p><strong>Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Threats Detected:</strong> {len(threats)}</p>
    </div>
    
    <h2>Threat Statistics</h2>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">{severity_counts.get('CRITICAL', 0)}</div>
            <div>Critical</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{severity_counts.get('ERROR', 0)}</div>
            <div>Error</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{severity_counts.get('WARNING', 0)}</div>
            <div>Warning</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{severity_counts.get('INFO', 0)}</div>
            <div>Info</div>
        </div>
    </div>
    
    <h2>Detected Threats</h2>
    
    {self._generate_threats_html(threats) if threats else '<div class="empty-message">No threats detected during this period.</div>'}
    
    <div style="margin-top: 30px; text-align: center; color: #7f8c8d; font-size: 12px;">
        <p>AI Security Logger v1.0 - Powered by OpenRouter API</p>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_threats_html(self, threats: List[Dict[str, Any]]) -> str:
        """Generate HTML for the threats section"""
        if not threats:
            return '<div class="empty-message">No threats detected during this period.</div>'
            
        threats_html = ""
        
        for threat in threats:
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
                
                # Build the threat HTML
                threats_html += f"""
    <div class="threat">
        <div class="threat-header">
            <h3>{summary}</h3>
            <span class="severity {severity}">{severity}</span>
        </div>
        <p><strong>Time:</strong> {timestamp}</p>
        <p><strong>Details:</strong> {threat.get('details', 'No details available')}</p>
        
        {f'<p><strong>Recommended Actions:</strong> {threat.get("recommended_actions", "")}</p>' if threat.get('recommended_actions') else ''}
        
        <details>
            <summary>Log Entries</summary>
            <div class="log-entries">{log_entries_html}</div>
        </details>
    </div>
"""
            except Exception as e:
                self.logger.error(f"Error formatting threat for HTML: {e}")
                threats_html += f"""
    <div class="threat">
        <div class="threat-header">
            <h3>Error Processing Threat</h3>
            <span class="severity WARNING">WARNING</span>
        </div>
        <p>There was an error processing this threat data.</p>
    </div>
"""
        
        return threats_html
    
    def _count_by_severity(self, threats: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count threats by severity"""
        counts = {}
        
        for threat in threats:
            severity = threat.get('severity', 'UNKNOWN')
            counts[severity] = counts.get(severity, 0) + 1
        
        return counts
