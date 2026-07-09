"""
Security Tools API — Unified backend for ShieldView + RemFlow
Serves from seed-data.json with live import capabilities.

Endpoints:
  ShieldView:   /v1/assets, /v1/cves, /v1/findings, /v1/teams, /v1/executive, /v1/trends
  RemFlow:      /v1/remediations, /v1/deployments, /v1/endpoint-checks, /v1/gpo
  Cross-tool:   /v1/dashboard (unified stats), /v1/software-versions
  Webhooks:     /v1/webhooks/remediate, /v1/webhooks/deploy, /v1/webhooks/import
"""
import json, os, datetime, uuid, asyncio, threading, re
from pathlib import Path
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ── Paths ───────────────────────────────────────────────────────
BASE_DIR = Path(os.environ.get("SEED_DIR", os.path.dirname(os.path.abspath(__file__))))
SEED_PATH = Path(os.environ.get("SEED_PATH", BASE_DIR / "seed-data.json"))
CACHE_DIR = BASE_DIR / "cached"
DATA_LOCK = threading.Lock()

# ── Data Store ──────────────────────────────────────────────────
_store = {}  # populated at startup

def load_seed(path=None):
    p = path or SEED_PATH
    if not p.exists():
        print(f"[WARN] Seed file not found: {p}")
        return {}
    with open(p) as f:
        return json.load(f)

def reload_data():
    global _store
    with DATA_LOCK:
        _store = load_seed()
        _store.setdefault("assets", [])
        _store.setdefault("cves", {})
        _store.setdefault("findings", [])
        _store.setdefault("remediations", [])
        _store.setdefault("deployments", [])
        _store.setdefault("endpointChecks", [])
        _store.setdefault("gpoPolicies", [])
        _store.setdefault("teams", {})
        _store.setdefault("history", [])
        print(f"  Loaded {len(_store['assets'])} assets, {len(_store['cves'])} CVEs, "
              f"{len(_store['findings'])} findings, {len(_store['remediations'])} remediations, "
              f"{len(_store['deployments'])} deployments, "
              f"{len(_store['endpointChecks'])} endpoint checks, "
              f"{len(_store['gpoPolicies'])} GPO policies")
    return _store

# ── Webhook action models ───────────────────────────────────────
class RemediateRequest(BaseModel):
    cve: str
    targets: List[str]
    title: Optional[str] = None
    severity: Optional[str] = "Medium"

class DeployRequest(BaseModel):
    remediation_id: str
    package_type: Optional[str] = "Software Update Package"

class ImportRequest(BaseModel):
    source: str  # "scanner", "agents", "patches", "gpo", "assets", "all"
    file_path: Optional[str] = None

# ── Helpers ─────────────────────────────────────────────────────
def _dt():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def _findings_by_asset(asset_hostname):
    return [f for f in _store["findings"] if f.get("asset") == asset_hostname]

def _findings_by_cve(cve_id):
    return [f for f in _store["findings"] if f.get("cve") == cve_id]

def _finding_stats(findings_list):
    total = len(findings_list)
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings_list:
        s = f.get("severity", "Medium")
        sev[s] = sev.get(s, 0) + 1
    active = sum(1 for f in findings_list if f.get("state") == "Active")
    kev = sum(1 for f in findings_list if f.get("kev"))
    return {"total": total, "by_severity": sev, "active": active, "kev": kev}

def _cve_detail(cve_id):
    cves = _store.get("cves", {})
    cve = cves.get(cve_id)
    if not cve:
        return None
    aff = _findings_by_cve(cve_id)
    assets_with = list(set(f.get("asset") for f in aff))
    return {
        "cve": cve_id,
        "title": cve.get("title", ""),
        "severity": cve.get("severity", "Medium"),
        "cvss": cve.get("cvss", 0),
        "kev": cve.get("kev", False),
        "ransomware": cve.get("ransomware", False),
        "exploited": cve.get("exploited"),
        "due": cve.get("due"),
        "desc": cve.get("desc", ""),
        "fix": cve.get("fix", ""),
        "refs": cve.get("refs", []),
        "affected_assets": assets_with,
        "affected_count": len(assets_with),
        "findings": aff,
    }

# ── App ─────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[boot] Loading seed data...")
    reload_data()
    yield
    print("[shutdown] Data persisted in memory")

app = FastAPI(
    title="Security Tools API",
    version="1.0.0",
    description="Unified backend for ShieldView (vuln management) and RemFlow (remediation)",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://mrdchiang.github.io",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Status ──────────────────────────────────────────────────────
@app.get("/v1/status")
def get_status():
    m = _store.get("meta", {})
    return {
        "status": "ok",
        "generated": m.get("generated", "unknown"),
        "version": "1.0.0",
        "asset_count": len(_store.get("assets", [])),
        "cve_count": len(_store.get("cves", {})),
        "finding_count": len(_store.get("findings", [])),
        "remediation_count": len(_store.get("remediations", [])),
        "deployment_count": len(_store.get("deployments", [])),
    }

@app.post("/v1/reload")
def reload():
    reload_data()
    return {"status": "reloaded", "counts": get_status()}

# ── Assets ──────────────────────────────────────────────────────
@app.get("/v1/assets")
def list_assets(
    loc: str = Query(None, description="Filter by location"),
    os_filter: str = Query(None, alias="os", description="Filter by OS name"),
    search: str = Query(None, description="Search hostname"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    assets = _store.get("assets", [])
    results = []
    for a in assets:
        if loc and loc.lower() not in a.get("loc", "").lower():
            continue
        if os_filter and os_filter.lower() not in a.get("os", "").lower():
            continue
        if search and search.lower() not in a.get("hostname", "").lower():
            continue
        # Attach finding count
        findings = _findings_by_asset(a.get("hostname", ""))
        a = {**a}
        a["finding_count"] = len(findings)
        a["finding_summary"] = _finding_stats(findings)
        results.append(a)
    total = len(results)
    return {"items": results[offset:offset+limit], "total": total, "offset": offset, "limit": limit}

@app.get("/v1/assets/{hostname}")
def get_asset(hostname: str):
    assets = _store.get("assets", [])
    for a in assets:
        if a.get("hostname", "").lower() == hostname.lower():
            findings = _findings_by_asset(hostname)
            endpoint_checks = [c for c in _store.get("endpointChecks", [])
                              if c.get("hostname", "").lower() == hostname.lower()]
            gpo = [g for g in _store.get("gpoPolicies", [])
                  if g.get("hostname", "").lower() == hostname.lower()]
            return {
                **a,
                "findings": findings,
                "findings_summary": _finding_stats(findings),
                "endpoint_checks": endpoint_checks,
                "gpo_policies": gpo,
                "check_count": len(endpoint_checks),
                "gpo_count": len(gpo),
            }
    raise HTTPException(404, f"Asset {hostname} not found")

# ── CVEs ────────────────────────────────────────────────────────
@app.get("/v1/cves")
def list_cves(
    severity: str = Query(None),
    kev: bool = Query(None),
    search: str = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    cves = _store.get("cves", {})
    results = []
    for cve_id, cve in cves.items():
        if severity and cve.get("severity", "").lower() != severity.lower():
            continue
        if kev is not None and bool(cve.get("kev")) != kev:
            continue
        if search and search.lower() not in cve_id.lower() and search.lower() not in cve.get("title", "").lower():
            continue
        findings = _findings_by_cve(cve_id)
        results.append({
            "cve": cve_id,
            **cve,
            "affected_count": len(set(f.get("asset") for f in findings)),
            "finding_count": len(findings),
        })
    total = len(results)
    return {"items": results[offset:offset+limit], "total": total}

@app.get("/v1/cves/{cve_id}")
def get_cve(cve_id: str):
    result = _cve_detail(cve_id)
    if not result:
        raise HTTPException(404, f"CVE {cve_id} not found")
    return result

# ── Findings ────────────────────────────────────────────────────
@app.get("/v1/findings")
def list_findings(
    severity: str = Query(None),
    state: str = Query(None),
    cve: str = Query(None, description="Filter by CVE ID"),
    asset: str = Query(None, description="Filter by asset hostname"),
    kev: bool = Query(None),
    search: str = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    group_by_check: bool = Query(False),
):
    findings = _store.get("findings", [])
    results = []
    for f in findings:
        if severity and f.get("severity", "").lower() != severity.lower():
            continue
        if state and f.get("state", "").lower() != state.lower():
            continue
        if cve and cve.lower() not in f.get("cve", "").lower():
            continue
        if asset and asset.lower() not in f.get("asset", "").lower():
            continue
        if kev is not None and bool(f.get("kev")) != kev:
            continue
        if search:
            q = search.lower()
            if q not in f.get("cve", "").lower() and q not in f.get("asset", "").lower() and q not in f.get("check", "").lower():
                continue
        results.append(f)
    total = len(results)
    if group_by_check:
        grouped = {}
        for f in results:
            key = f.get("check", "Unknown")
            if key not in grouped:
                grouped[key] = {"check": key, "findings": [], "count": 0}
            grouped[key]["findings"].append(f)
            grouped[key]["count"] += 1
        return {"groups": list(grouped.values()), "total": total}
    return {"items": results[offset:offset+limit], "total": total}

# ── Remediations ────────────────────────────────────────────────
@app.get("/v1/remediations")
def list_remediations(
    status: str = Query(None),
    severity: str = Query(None),
    search: str = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    rems = _store.get("remediations", [])
    results = []
    for r in rems:
        if status and r.get("status", "").lower() != status.lower():
            continue
        if severity and r.get("severity", "").lower() != severity.lower():
            continue
        if search:
            q = search.lower()
            if q not in r.get("cve", "").lower() and q not in r.get("id", "").lower():
                continue
        results.append(r)
    total = len(results)
    return {"items": results[offset:offset+limit], "total": total}

@app.get("/v1/remediations/{rem_id}")
def get_remediation(rem_id: str):
    for r in _store.get("remediations", []):
        if r.get("id", "").lower() == rem_id.lower():
            return r
    raise HTTPException(404, f"Remediation {rem_id} not found")

# ── Deployments ─────────────────────────────────────────────────
@app.get("/v1/deployments")
def list_deployments(
    status: str = Query(None),
    search: str = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    deps = _store.get("deployments", [])
    results = []
    for d in deps:
        if status and d.get("status", "").lower() != status.lower():
            continue
        if search:
            q = search.lower()
            if q not in d.get("id", "").lower() and q not in d.get("package", "").lower():
                continue
        results.append(d)
    total = len(results)
    return {"items": results[offset:offset+limit], "total": total}

@app.get("/v1/deployments/{dep_id}")
def get_deployment(dep_id: str):
    for d in _store.get("deployments", []):
        if d.get("id", "").lower() == dep_id.lower():
            return d
    raise HTTPException(404, f"Deployment {dep_id} not found")

# ── Endpoint Checks (TheValidator / RemFlow health) ─────────────
@app.get("/v1/endpoint-checks")
def list_endpoint_checks(
    hostname: str = Query(None),
    passed: bool = Query(None),
    severity: str = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
):
    checks = _store.get("endpointChecks", [])
    results = []
    for c in checks:
        if hostname and c.get("hostname", "").lower() != hostname.lower():
            continue
        if passed is not None and bool(c.get("passed")) != passed:
            continue
        if severity and c.get("severity", "").lower() != severity.lower():
            continue
        results.append(c)
    total = len(results)
    return {"items": results[offset:offset+limit], "total": total}

# ── GPO Compliance ─────────────────────────────────────────────
@app.get("/v1/gpo")
def list_gpo(
    hostname: str = Query(None),
    compliant: bool = Query(None),
    critical: bool = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
):
    policies = _store.get("gpoPolicies", [])
    results = []
    for g in policies:
        if hostname and g.get("hostname", "").lower() != hostname.lower():
            continue
        if compliant is not None and bool(g.get("compliant")) != compliant:
            continue
        if critical is not None and bool(g.get("critical")) != critical:
            continue
        results.append(g)
    total = len(results)
    return {"items": results[offset:offset+limit], "total": total}

# ── Teams ───────────────────────────────────────────────────────
@app.get("/v1/teams")
def list_teams():
    teams = _store.get("teams", {})
    return teams

@app.get("/v1/teams/{team_slug}")
def get_team(team_slug: str):
    teams = _store.get("teams", {})
    team = teams.get(team_slug)
    if not team:
        raise HTTPException(404, f"Team {team_slug} not found")
    # Enrich with findings
    assets_list = team.get("assets_list", [])
    all_findings = []
    for a in assets_list:
        hn = a.get("name", "")
        all_findings.extend(_findings_by_asset(hn))
    return {**team, "findings": all_findings, "finding_stats": _finding_stats(all_findings)}

# ── Dashboard / Stats ───────────────────────────────────────────
@app.get("/v1/dashboard")
def get_dashboard():
    findings = _store.get("findings", [])
    assets = _store.get("assets", [])
    cves = _store.get("cves", {})
    rems = _store.get("remediations", [])
    deps = _store.get("deployments", [])

    all_stats = _finding_stats(findings)
    active_findings = [f for f in findings if f.get("state") == "Active"]
    active_cves = set(f.get("cve") for f in active_findings)

    # Severity breakdown
    sev_counts = all_stats["by_severity"]
    sev_kev = {}
    for f in active_findings:
        if f.get("kev"):
            s = f.get("severity", "Medium")
            sev_kev[s] = sev_kev.get(s, 0) + 1

    # Aged > 90 days (approximate — check firstSeen)
    aged = 0
    for f in active_findings:
        first = f.get("firstSeen", "")
        if first:
            try:
                dt = datetime.datetime.strptime(str(first)[:10], "%Y-%m-%d")
                if (datetime.datetime.now() - dt).days > 90:
                    aged += 1
            except:
                pass

    # Recent deployments
    recent_deps = sorted(deps, key=lambda d: d.get("start", ""), reverse=True)[:5]

    return {
        "total_findings": all_stats["total"],
        "active_findings": all_stats["active"],
        "distinct_cves": len(active_cves),
        "critical": sev_counts.get("Critical", 0),
        "high": sev_counts.get("High", 0),
        "medium": sev_counts.get("Medium", 0),
        "low": sev_counts.get("Low", 0),
        "kev_critical": sev_kev.get("Critical", 0),
        "kev_high": sev_kev.get("High", 0),
        "kev_medium": sev_kev.get("Medium", 0),
        "total_kev": sum(sev_kev.values()),
        "aged_over_90": aged,
        "unactioned": len([f for f in findings if f.get("disposition") == "Open"]),
        "asset_count": len(assets),
        "remediation_count": len(rems),
        "deployment_count": len(deps),
        "auto_remediation_rate": round(
            sum(1 for r in rems if r.get("status") == "Completed") / max(len(rems), 1) * 100, 1
        ),
        "recent_deployments": recent_deps,
        "top_cves": _top_cves(active_findings, 5),
    }

def _top_cves(findings, n=5):
    counts = {}
    for f in findings:
        c = f.get("cve", "")
        counts[c] = counts.get(c, 0) + 1
    sorted_cves = sorted(counts.items(), key=lambda x: -x[1])[:n]
    result = []
    for cve_id, count in sorted_cves:
        cves = _store.get("cves", {})
        cve = cves.get(cve_id, {})
        result.append({
            "cve": cve_id,
            "title": cve.get("title", ""),
            "severity": cve.get("severity", "Medium"),
            "affected": count,
            "kev": cve.get("kev", False),
        })
    return result

# ── Executive / Trends ──────────────────────────────────────────
@app.get("/v1/executive")
def get_executive():
    findings = _store.get("findings", [])
    assets = _store.get("assets", [])
    cves = _store.get("cves", {})
    rems = _store.get("remediations", [])

    active = [f for f in findings if f.get("state") == "Active"]
    fixed = [f for f in findings if f.get("state") == "Fixed"]

    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in active:
        s = f.get("severity", "Medium")
        sev[s] = sev.get(s, 0) + 1

    kev_count = sum(1 for f in active if f.get("kev"))
    kev_cves = set(f.get("cve") for f in active if f.get("kev"))

    # Per-team breakdown
    teams_data = _store.get("teams", {})
    team_breakdown = {}
    for slug, team in teams_data.items():
        team_findings = []
        for a in team.get("assets_list", []):
            hn = a.get("name", "")
            team_findings.extend(_findings_by_asset(hn))
        team_breakdown[slug] = {
            "name": team.get("name", slug),
            **{k: v for k, v in _finding_stats(team_findings).items()},
            "assets": len(team.get("assets_list", [])),
        }

    return {
        "total_active": len(active),
        "total_fixed": len(fixed),
        "by_severity": sev,
        "kev_active": kev_count,
        "kev_cves": len(kev_cves),
        "total_cves": len(cves),
        "assets": len(assets),
        "teams": team_breakdown,
        "fix_rate": round(len(fixed) / max(len(findings), 1) * 100, 1),
        "remediation_coverage": round(
            sum(1 for r in rems if r.get("status") == "Completed") / max(len(rems), 1) * 100, 1
        ),
    }

@app.get("/v1/trends")
def get_trends(period: str = Query("30d", pattern="^(7d|30d|90d)$")):
    """Return simple trend data from the history store."""
    history = _store.get("history", [])
    # History items: {date, total, critical, high, medium, low}
    return {"period": period, "data_points": history}

# ── Recently Fixed ──────────────────────────────────────────────
@app.get("/v1/recently-fixed")
def get_recently_fixed(days: int = Query(30, ge=1, le=365)):
    findings = _store.get("findings", [])
    fixed = [f for f in findings if f.get("state") == "Fixed"]
    # Simple by-cve grouping
    by_cve = {}
    for f in fixed:
        c = f.get("cve", "")
        if c not in by_cve:
            cves = _store.get("cves", {})
            cv = cves.get(c, {})
            by_cve[c] = {"cve": c, "title": cv.get("title", ""), "assets": []}
        by_cve[c]["assets"].append(f.get("asset", ""))
    for v in by_cve.values():
        v["asset_count"] = len(set(v["assets"]))
    return {"items": list(by_cve.values())}

# ── RemFlow Dashboard (remediation-focused) ─────────────────────
@app.get("/v1/remflow/dashboard")
def get_remflow_dashboard():
    findings = _store.get("findings", [])
    rems = _store.get("remediations", [])
    deps = _store.get("deployments", [])

    total = len(findings)
    auto_rem = sum(1 for f in findings if f.get("state") == "Fixed")
    pending = sum(1 for f in findings if f.get("state") == "Active")
    failed = sum(1 for r in rems if r.get("status") == "Failed")

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        s = f.get("severity", "Medium")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    rem_status = {}
    for r in rems:
        s = r.get("status", "Unknown")
        rem_status[s] = rem_status.get(s, 0) + 1

    recent_rems = sorted(rems, key=lambda r: r.get("created", ""), reverse=True)[:5]
    recent_deps = sorted(deps, key=lambda d: d.get("start", ""), reverse=True)[:5]

    return {
        "total_findings": total,
        "auto_remediated": auto_rem,
        "auto_rate": round(auto_rem / max(total, 1) * 100, 1),
        "pending_review": pending,
        "failed_remediations": failed,
        "by_severity": sev_counts,
        "remediation_status": rem_status,
        "assets_monitored": len(_store.get("assets", [])),
        "recent_remediations": recent_rems,
        "recent_deployments": recent_deps,
    }

# ── Health Summary (TheValidator compatible) ────────────────────
@app.get("/v1/health")
def get_health_summary():
    checks = _store.get("endpointChecks", [])
    total = len(checks)
    passed = sum(1 for c in checks if c.get("passed"))
    failed = total - passed
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for c in checks:
        if not c.get("passed"):
            s = c.get("severity", "Medium")
            by_severity[s] = by_severity.get(s, 0) + 1
    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": round(passed / max(total, 1) * 100, 1),
        "failed_by_severity": by_severity,
    }

# ── Software Versions (from TheValidator) ───────────────────────
@app.get("/v1/software-versions")
async def get_software_versions():
    """Return IT software version compliance data.
    Uses live fetch from 20+ vendor APIs with fallback.
    """
    import importlib.util
    try:
        spec = importlib.util.spec_from_file_location(
            "pull_patches",
            os.path.join(BASE_DIR, "pull_patches.py") if BASE_DIR != Path(".") else None
        )
        if spec:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "fetch_software_versions"):
                return await mod.fetch_software_versions()
    except Exception:
        pass
    # Fallback — return from cached
    cached_file = CACHE_DIR / "patches.json"
    if cached_file.exists():
        with open(cached_file) as f:
            return json.load(f)
    return {"items": [], "source": "demo"}

# ── Webhooks / Actions ──────────────────────────────────────────
@app.post("/v1/webhooks/remediate")
def webhook_remediate(req: RemediateRequest):
    """Create a new remediation from ShieldView findings."""
    with DATA_LOCK:
        rems = _store.get("remediations", [])
        new_id = f"RM-{len(rems):04d}"
        new_rem = {
            "id": new_id,
            "cve": req.cve,
            "title": req.title or "",
            "severity": req.severity,
            "targets": list(set(req.targets)),
            "targetCount": len(set(req.targets)),
            "status": "Queued",
            "created": _dt(),
            "completed": "—",
            "coverage": 0,
        }
        rems.append(new_rem)
        # Find the CVE title if not provided
        if not req.title:
            cves = _store.get("cves", {})
            cve = cves.get(req.cve)
            if cve:
                new_rem["title"] = cve.get("title", "")
    return {"status": "created", "remediation": new_rem}

@app.post("/v1/webhooks/deploy")
def webhook_deploy(req: DeployRequest):
    """Trigger a deployment from a remediation."""
    with DATA_LOCK:
        # Find the remediation
        rem = None
        for r in _store.get("remediations", []):
            if r.get("id", "").lower() == req.remediation_id.lower():
                rem = r
                break
        if not rem:
            raise HTTPException(404, f"Remediation {req.remediation_id} not found")
        # Update it
        rem["status"] = "In Progress"
        # Create a deployment record
        deps = _store.get("deployments", [])
        new_id = f"DEP-{len(deps):04d}"
        new_dep = {
            "id": new_id,
            "package": f"PatchFlow-{len(deps):04d}",
            "type": req.package_type,
            "cve": rem.get("cve", ""),
            "targetCount": rem.get("targetCount", 0),
            "successRate": 0,
            "start": _dt(),
            "end": "—",
            "status": "In Progress",
            "remediation_id": req.remediation_id,
        }
        deps.append(new_dep)
    return {"status": "deploying", "remediation": rem, "deployment": new_dep}

@app.post("/v1/webhooks/import")
def webhook_import(req: ImportRequest, background_tasks: BackgroundTasks):
    """Trigger a data import via the connector scripts."""
    def _run_import(source):
        script_map = {
            "scanner": "pull_vulns.py",
            "agents": "pull_agents.py",
            "patches": "pull_patches.py",
            "gpo": "pull_gpo.py",
            "assets": "pull_assets.py",
            "all": "merge_seed.py",
        }
        script = script_map.get(source)
        if not script:
            return
        script_path = os.path.join(BASE_DIR, script)
        if os.path.exists(script_path):
            import subprocess
            result = subprocess.run(
                ["python", script_path],
                capture_output=True, text=True, cwd=BASE_DIR,
                timeout=120,
            )
            print(f"[import:{source}] exit={result.returncode}: {result.stdout[:200]}")
            if result.returncode == 0:
                reload_data()
    background_tasks.add_task(_run_import, req.source)
    return {
        "status": "import_started",
        "source": req.source,
        "note": "Import running in background. Call /v1/reload when done."
    }

# ── Health-check endpoint (for Render/Fly.io) ───────────────────
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# ── Main ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
