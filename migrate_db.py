
#!/usr/bin/env python3
"""
Database migration script for M3U Player
Creates all necessary tables and indexes
"""

import os
from app import app, db

def create_database():
    """Create all database tables"""
    with app.app_context():
        print("Creating database tables...")
        
        # Drop all tables first (fresh start)
        db.drop_all()
        print("Dropped existing tables")
        
        # Create all tables
        db.create_all()
        print("Created new tables")
        
        # Verify tables were created
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"Created tables: {tables}")
        
        print("Database migration completed successfully!")

if __name__ == '__main__':
    create_database()
