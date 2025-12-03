"""
Manually delete all users from database
"""
import asyncio
from app.core.database import engine
from sqlmodel import select
from app.models.user import User
from app.models.email_verification import EmailVerification
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker


async def delete_all_data():
    """Delete all users and email verifications"""
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        # Delete all email verifications first
        result_verif = await session.execute(select(EmailVerification))
        verifications = result_verif.scalars().all()
        for v in verifications:
            await session.delete(v)
        
        # Delete all users
        result_users = await session.execute(select(User))
        users = result_users.scalars().all()
        for user in users:
            await session.delete(user)
        
        await session.commit()
        
        print(f"Deleted {len(verifications)} email verifications")
        print(f"Deleted {len(users)} users")
        print("\nDatabase is now empty!")


if __name__ == "__main__":
    asyncio.run(delete_all_data())
