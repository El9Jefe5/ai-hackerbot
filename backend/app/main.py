from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import assessments, auth, targets
from app.core.db import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)  # adds new tables only; Alembic arrives with the first column change
    yield


app = FastAPI(title="AI HackerBot API", version="0.2.0", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(assessments.router)


@app.get("/health")
def health():
    return {"status": "ok"}
