from fastapi import FastAPI

from app.api import auth, targets
from app.core.db import Base, engine

app = FastAPI(title="AI HackerBot API", version="0.1.0")
app.include_router(auth.router)
app.include_router(targets.router)


@app.on_event("startup")
def _init():
    Base.metadata.create_all(engine)  # replaced by Alembic migrations in M2


@app.get("/health")
def health():
    return {"status": "ok"}
