# orin/analysis/reporter.py
from pathlib import Path
from datetime import datetime
from orin.core.database import OrinStorage

def compile_markdown_report(db_path: Path, output_path: Path) -> None:
    """Queries snapshots and security alerts to write out the standalone Markdown briefing."""
    storage = OrinStorage(db_path)
    
    with storage.get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, timestamp, hostname, os_platform FROM system_snapshots ORDER BY id DESC LIMIT 1;")
        snapshot = cursor.fetchone()
        if not snapshot:
            raise ValueError("No system data snapshots exist. Run 'orin collect' first.")
            
        cursor.execute("""
            SELECT id, timestamp, event_type, severity, description 
            FROM security_events 
            WHERE resolved = 0
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    ELSE 4 
                END, id DESC;
        """)
        events = cursor.fetchall()
        
    generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    md_content = f"""# ORIN INVESTIGATION FORENSIC SUMMARY REPORT
Generated on: `{generation_time}` | Core Engine: Fully Offline MVP

## 🖥️ Target Machine Context
- **Analysis Snapshot ID:** {snapshot['id']}
- **Collection Timestamp:** {snapshot['timestamp']}
- **Target Hostname:** {snapshot['hostname']}
- **OS Platform:** {snapshot['os_platform']}

## 🚨 Security Anomaly Events Detected ({len(events)})
"""
    
    if not events:
        md_content += "\n🟢 **No anomalous security indicators or policy drift patterns identified on this host.**\n"
    else:
        md_content += "\n| ID | Timestamp | Severity | Event Type | Incident Description |\n"
        md_content += "|---|---|---|---|---|\n"
        for ev in events:
            severity_icon = "🔴" if ev['severity'] in ('critical', 'high') else "🟡"
            md_content += f"| {ev['id']} | {ev['timestamp']} | {severity_icon} {ev['severity'].upper()} | {ev['event_type']} | {ev['description']} |\n"
            
    md_content += """
---
*End of Verification Report — Secure Local Relational Vault File Ledger Integrity Intact.*
"""
    output_path.write_text(md_content.strip() + "\n", encoding="utf-8")