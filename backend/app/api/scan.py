from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import Site, Snapshot, Alert, User, Role
from app.schemas.schemas import ScanResult
from app.core.security import get_current_user, require_role, require_same_org
from app.services.scanner import run_full_scan, score_from_scan
from app.services.ai import generate_summary
from app.services.audit import log_action

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/{site_id}", response_model=ScanResult)
async def scan_site(
    site_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(Role.ANALYST)),  # Viewer cannot trigger scans
):
    site = db.query(Site).filter(Site.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    require_same_org(site.org_id, current_user)

    scan = await run_full_scan(site.url)
    score = score_from_scan(scan)

    prev = (
        db.query(Snapshot)
        .filter(Snapshot.site_id == site.id)
        .order_by(Snapshot.created_at.desc())
        .first()
    )
    defacement_suspected = bool(prev and prev.html_hash != scan.get("html_hash"))

    snapshot = Snapshot(
        site_id=site.id,
        html_hash=scan.get("html_hash", ""),
        headers=scan.get("headers"),
        scan_result=scan,
        security_score=str(score),
    )
    db.add(snapshot)

    if defacement_suspected:
        db.add(Alert(
            site_id=site.id,
            severity="SL-1",
            title="Content change detected (possible defacement)",
            description="HTML hash differs from previous snapshot.",
        ))

    if score < 60:
        db.add(Alert(
            site_id=site.id,
            severity="SL-2",
            title=f"Low security score: {score}/100",
            description="Multiple missing security headers or SSL issues detected.",
        ))

    db.commit()
    log_action(db, current_user.org_id, current_user.id, "scan_site", "site", {"site_id": site_id, "score": score})

    ai_summary = await generate_summary(scan, score)
    return ScanResult(scan=scan, score=score, ai_summary=ai_summary)
