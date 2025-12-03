"""Check what users are in the database"""
import asyncio
from app.core.database import engine
from sqlmodel import select
from app.models.user import User
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker


async def check_users():
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        
        print(f"Total users in database: {len(users)}")
        if users:
            print("\nUsers found:")
            for user in users:
                print(f"  - Email: {user.email}")
                print(f"    Verified: {user.is_email_verified}")
                print(f"    ID: {user.id}")
        else:
            print("Database is empty - no users found!")


if __name__ == "__main__":
    asyncio.run(check_users())
