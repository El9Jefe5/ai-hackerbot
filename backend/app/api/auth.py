from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import create_token, hash_password, verify_password
from app.models import AuditLog, User

router = APIRouter(prefix="/auth", tags=["auth"])


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=10, max_length=128)


@router.post("/register", status_code=201)
def register(body: Credentials, db: Session = Depends(get_db)):
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already registered")
    user = User(email=email, password_hash=hash_password(body.password))  # always 'analyst'
    db.add(user)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="user.register", detail=email))
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role}


@router.post("/login")
def login(body: Credentials, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not verify_password(body.password, user.password_hash):
        db.add(AuditLog(action="auth.failed", detail=body.email.lower()))
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    return {"access_token": create_token(user), "token_type": "bearer"}
