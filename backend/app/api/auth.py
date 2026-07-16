from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import User, Organization, Role
from app.schemas.schemas import OrgCreate, TokenResponse, LoginRequest
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token, decode_token, get_current_user
from app.services.audit import log_action

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/signup", response_model=TokenResponse)
def signup(payload: OrgCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    org = Organization(name=payload.org_name)
    db.add(org)
    db.flush()  # get org.id without full commit

    user = User(
        org_id=org.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=Role.OWNER,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_action(db, org.id, user.id, "signup", "organization", {"org_name": org.name})

    return TokenResponse(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # NOTE: generic error message on both "no such user" and "wrong password" —
    # prevents user-enumeration (a common SL-2/SL-3 finding).
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    log_action(db, user.org_id, user.id, "login", "user")

    return TokenResponse(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str, db: Session = Depends(get_db)):
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return TokenResponse(
        access_token=create_access_token(user.id),
        refresh_token=create_refresh_token(user.id),
    )


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "role": current_user.role,
        "org_id": current_user.org_id,
        "org_name": current_user.organization.name
    }

