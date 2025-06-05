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
            # Ensure log_entries is a serializable format
            log_entries = threat_data.get('log_entries', [])
            
            try:
                # Test if it can be serialized directly
                log_entries_json = json.dumps(log_entries)
            except (TypeError, ValueError) as json_error:
                # If not, convert to a simpler format
                self.logger.warning(f"Converting log entries to simple format due to serialization error: {json_error}")
                simplified_entries = []
                for entry in log_entries:
                    if isinstance(entry, dict):
                        # Keep only serializable fields
                        simple_entry = {
                            'source_file': str(entry.get('source_file', 'unknown')),
                            'log_type': str(entry.get('log_type', 'unknown')),
                            'raw_line': str(entry.get('raw_line', '')),
                        }
                        simplified_entries.append(simple_entry)
                    else:
                        # If it's not a dict, convert to string
                        simplified_entries.append(str(entry))
                
                log_entries_json = json.dumps(simplified_entries)
            
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
            
            self.logger.debug(f"Executing query: {query} with params: {params}")
            
            # Execute query
            async with self.db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                
                self.logger.debug(f"Found {len(rows)} threats in database")
                
                # Convert rows to dictionaries
                threats = []
                for row in rows:
                    try:
                        log_entries_json = row[8]
                        log_entries = json.loads(log_entries_json) if log_entries_json else []
                        
                        threat = {
                            'id': row[0],
                            'timestamp': row[1],
                            'detected_at': row[2],
                            'threat_detected': bool(row[3]),
                            'severity': row[4],
                            'summary': row[5],
                            'details': row[6],
                            'recommended_actions': row[7],
                            'log_entries': log_entries
                        }
                        threats.append(threat)
                    except Exception as row_error:
                        self.logger.error(f"Error processing threat row: {row_error}")
                
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
            cursor = await self.db.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
            await self.db.commit()
            
            # Check if any rows were affected
            rows_affected = cursor.rowcount
            if rows_affected > 0:
                self.logger.info(f"Deleted threat with ID {threat_id}")
                return True
            else:
                self.logger.warning(f"No threat found with ID {threat_id}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error deleting threat: {e}")
            return False
