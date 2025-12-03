"""
Database management script for development.
Clear database and recreate tables.
"""
import asyncio
from app.core.database import engine
from sqlmodel import SQLModel


async def clear_database():
    """Drop all tables and recreate them."""
    print("WARNING: This will delete ALL data from the database!")
    confirm = input("Type 'yes' to continue: ")
    
    if confirm.lower() != 'yes':
        print("Operation cancelled.")
        return
    
    print("\nDropping all tables...")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    
    print("All tables dropped!")
    
    print("\nCreating fresh tables...")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    print("Database cleared and recreated!")
    print("\nYou can now register with jayworthjohn@gmail.com again.")


if __name__ == "__main__":
    asyncio.run(clear_database())
