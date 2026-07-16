from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, EmailStr, field_validator


class OrgCreate(BaseModel):
    org_name: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    org_id: str

    class Config:
        from_attributes = True


class SiteCreate(BaseModel):
    name: str
    url: str


class SiteOut(BaseModel):
    id: str
    name: str
    url: str
    created_at: datetime

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: str
    site_id: str
    severity: str
    title: str
    description: Optional[str]
    resolved: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResult(BaseModel):
    scan: dict[str, Any]
    score: int
    ai_summary: Optional[dict[str, Any]] = None
