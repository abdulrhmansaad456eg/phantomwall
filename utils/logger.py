import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import asdict


class LogManager:
    def __init__(self, db_path: str = "phantomwall_logs.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                payload TEXT,
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                request_id TEXT UNIQUE NOT NULL,
                headers TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_attack_type ON security_events(attack_type)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_source_ip ON security_events(source_ip)
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT UNIQUE NOT NULL,
                total_requests INTEGER DEFAULT 0,
                blocked_requests INTEGER DEFAULT 0,
                detections INTEGER DEFAULT 0
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_event(self, event) -> bool:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO security_events 
                (timestamp, attack_type, threat_level, source_ip, method, path, 
                 payload, action, rule_id, request_id, headers, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp,
                event.attack_type,
                event.threat_level,
                event.source_ip,
                event.method,
                event.path,
                event.payload[:1000] if event.payload else "",
                event.action,
                event.rule_id,
                event.request_id,
                json.dumps(event.headers),
                event.user_agent
            ))
            
            conn.commit()
            conn.close()
            self._update_stats(event.action == "blocked")
            return True
        except Exception:
            return False
    
    def _update_stats(self, was_blocked: bool):
        today = datetime.now().strftime("%Y-%m-%d")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO request_stats (date, total_requests, blocked_requests, detections)
            VALUES (?, 1, ?, 1)
            ON CONFLICT(date) DO UPDATE SET
                total_requests = total_requests + 1,
                blocked_requests = blocked_requests + ?,
                detections = detections + 1
        """, (today, 1 if was_blocked else 0, 1 if was_blocked else 0))
        
        conn.commit()
        conn.close()
    
    def get_events(self, 
                   limit: int = 100, 
                   offset: int = 0,
                   attack_type: Optional[str] = None,
                   threat_level: Optional[str] = None,
                   source_ip: Optional[str] = None,
                   start_date: Optional[str] = None,
                   end_date: Optional[str] = None) -> List[Dict]:
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []
        
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)
        
        if threat_level:
            query += " AND threat_level = ?"
            params.append(threat_level)
        
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
        
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_event_by_id(self, event_id: int) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM security_events WHERE id = ?", (event_id,))
        row = cursor.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def get_stats(self, days: int = 7) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT source_ip) as unique_ips,
                SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
                SUM(CASE WHEN action = 'logged' THEN 1 ELSE 0 END) as logged_count
            FROM security_events
            WHERE timestamp >= date('now', '-{} days')
        """.format(days))
        
        row = cursor.fetchone()
        
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM security_events
            WHERE timestamp >= date('now', '-{} days')
            GROUP BY attack_type
            ORDER BY count DESC
        """.format(days))
        
        attack_types = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT threat_level, COUNT(*) as count
            FROM security_events
            WHERE timestamp >= date('now', '-{} days')
            GROUP BY threat_level
        """.format(days))
        
        threat_levels = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT date(timestamp) as day, COUNT(*) as count
            FROM security_events
            WHERE timestamp >= date('now', '-{} days')
            GROUP BY day
            ORDER BY day
        """.format(days))
        
        timeline = [{"date": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "total_events": row[0] or 0,
            "unique_ips": row[1] or 0,
            "blocked_count": row[2] or 0,
            "logged_count": row[3] or 0,
            "attack_types": attack_types,
            "threat_levels": threat_levels,
            "timeline": timeline
        }
    
    def get_recent_events(self, limit: int = 10) -> List[Dict]:
        return self.get_events(limit=limit)
    
    def clear_old_logs(self, days: int = 30) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute("DELETE FROM security_events WHERE timestamp < ?", (cutoff,))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def export_logs(self, format_type: str = "json", 
                   start_date: Optional[str] = None,
                   end_date: Optional[str] = None) -> str:
        events = self.get_events(
            limit=10000,
            start_date=start_date,
            end_date=end_date
        )
        
        if format_type == "json":
            return json.dumps(events, indent=2, ensure_ascii=False)
        elif format_type == "csv":
            if not events:
                return ""
            
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
            return output.getvalue()
        
        return ""
    
    def get_attack_type_distribution(self) -> Dict[str, int]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM security_events
            GROUP BY attack_type
            ORDER BY count DESC
        """)
        
        result = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        
        return result
    
    def get_top_blocked_ips(self, limit: int = 10) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM security_events
            WHERE action = 'blocked'
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        
        result = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
        conn.close()
        
        return result
