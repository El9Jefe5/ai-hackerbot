from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import auth, targets
from app.core.db import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)  # replaced by Alembic migrations in M2
    yield


app = FastAPI(title="AI HackerBot API", version="0.1.0", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(targets.router)


@app.get("/health")
def health():
    return {"status": "ok"}
