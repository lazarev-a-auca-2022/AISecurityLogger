"""
Database - Handles storage and retrieval of threat data
"""

import aiosqlite
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


class Database:
    """Database handler for storing and retrieving threat data"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.db = None
        
        # Ensure directory exists
        os.makedirs(Path(db_path).parent, exist_ok=True)
    
    async def initialize(self):
        """Initialize the database and create tables if they don't exist"""
        try:
            self.db = await aiosqlite.connect(self.db_path)
            
            # Create tables
            await self.db.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    detected_at TEXT NOT NULL,
                    threat_detected BOOLEAN NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    details TEXT,
                    recommended_actions TEXT,
                    log_entries TEXT NOT NULL
                )
            ''')
            
            await self.db.commit()
            self.logger.info(f"Database initialized at {self.db_path}")
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    async def close(self):
        """Close the database connection"""
        if self.db:
            await self.db.close()
            self.logger.info("Database connection closed")
    
    async def store_threat(self, threat_data: Dict[str, Any]) -> int:
        """Store a threat in the database"""
        try:
            # Convert log entries to JSON string
            log_entries_json = json.dumps(threat_data.get('log_entries', []))
            
            # Insert threat into database
            cursor = await self.db.execute('''
                INSERT INTO threats 
                (timestamp, detected_at, threat_detected, severity, summary, details, 
                recommended_actions, log_entries)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_data.get('timestamp', datetime.now().timestamp()),
                datetime.now().isoformat(),
                threat_data.get('threat_detected', False),
                threat_data.get('severity', 'INFO'),
                threat_data.get('summary', ''),
                threat_data.get('details', ''),
                threat_data.get('recommended_actions', ''),
                log_entries_json
            ))
            
            await self.db.commit()
            
            # Get the ID of the inserted row
            threat_id = cursor.lastrowid
            self.logger.info(f"Stored threat with ID {threat_id}")
            
            return threat_id
            
        except Exception as e:
            self.logger.error(f"Error storing threat: {e}")
            return -1
    
    async def get_threats(self, 
                         limit: int = 100, 
                         offset: int = 0, 
                         severity: Optional[str] = None,
                         start_time: Optional[float] = None,
                         end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Get threats from the database with optional filtering"""
        try:
            query = "SELECT * FROM threats WHERE 1=1"
            params = []
            
            # Add filters
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            
            # Add order and limit
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            # Execute query
            async with self.db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                
                # Convert rows to dictionaries
                threats = []
                async for row in cursor:
                    threat = {
                        'id': row[0],
                        'timestamp': row[1],
                        'detected_at': row[2],
                        'threat_detected': bool(row[3]),
                        'severity': row[4],
                        'summary': row[5],
                        'details': row[6],
                        'recommended_actions': row[7],
                        'log_entries': json.loads(row[8])
                    }
                    threats.append(threat)
                
                return threats
                
        except Exception as e:
            self.logger.error(f"Error getting threats: {e}")
            return []
    
    async def get_threat_by_id(self, threat_id: int) -> Optional[Dict[str, Any]]:
        """Get a threat by its ID"""
        try:
            async with self.db.execute("SELECT * FROM threats WHERE id = ?", (threat_id,)) as cursor:
                row = await cursor.fetchone()
                
                if row:
                    threat = {
                        'id': row[0],
                        'timestamp': row[1],
                        'detected_at': row[2],
                        'threat_detected': bool(row[3]),
                        'severity': row[4],
                        'summary': row[5],
                        'details': row[6],
                        'recommended_actions': row[7],
                        'log_entries': json.loads(row[8])
                    }
                    return threat
                
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting threat by ID: {e}")
            return None
    
    async def get_threats_count(self, 
                              severity: Optional[str] = None,
                              start_time: Optional[float] = None,
                              end_time: Optional[float] = None) -> int:
        """Get count of threats with optional filtering"""
        try:
            query = "SELECT COUNT(*) FROM threats WHERE 1=1"
            params = []
            
            # Add filters
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            
            # Execute query
            async with self.db.execute(query, params) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else 0
                
        except Exception as e:
            self.logger.error(f"Error getting threats count: {e}")
            return 0
    
    async def delete_threat(self, threat_id: int) -> bool:
        """Delete a threat by its ID"""
        try:
            await self.db.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
            await self.db.commit()
            self.logger.info(f"Deleted threat with ID {threat_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting threat: {e}")
            return False
