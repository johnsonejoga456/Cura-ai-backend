from fastapi import FastAPI
from app.api.endpoints import auth
from app.core.database import init_db

app = FastAPI(title="Cura AI Backend")

@app.on_event("startup")
async def on_startup():
    await init_db()

app.include_router(auth.router, prefix="/auth", tags=["auth"])

@app.get("/")
async def root():
    return {"message": "Welcome to Cura AI Backend"}
