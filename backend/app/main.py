import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.db.session import Base, engine
from app.api import auth, sites, scan, alerts

app = FastAPI(title="Website Defacement & Vulnerability Assessment Platform")

# Strict CORS — only allow the configured frontend origin(s), never "*".
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


@app.on_event("startup")
def on_startup():
    # For hackathon speed we create tables directly; use Alembic migrations for real prod use.
    Base.metadata.create_all(bind=engine)


@app.get("/api/health")
def health():
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(sites.router)
app.include_router(scan.router)
app.include_router(alerts.router)
