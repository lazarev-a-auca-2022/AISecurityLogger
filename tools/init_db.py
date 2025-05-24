"""
Database Initialization Script
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.database import Database


async def init_db():
    """Initialize the database"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    try:
        # Get database path from environment or use default
        db_path = os.getenv('DB_PATH', '/app/data/db/threats.db')
        
        # Create database directory if it doesn't exist
        os.makedirs(Path(db_path).parent, exist_ok=True)
        
        logger.info(f"Initializing database at {db_path}")
        
        # Initialize database
        db = Database(db_path)
        await db.initialize()

        # Close database connection
        await db.close()
        
        logger.info("Database initialized successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(init_db())
    sys.exit(exit_code)
