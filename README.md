# ── Security Tools API ───────────────────────────────────────────
# Unified backend for ShieldView + RemFlow
#
# Deploy options:
#   1. Windows Self-Host (Recommended): run start_windows.bat or install as Windows service
#   2. Docker: docker build -t security-tools-api . && docker run -p 8000:8000 security-tools-api
#   3. Render: Connect repo, set Start Command to "uvicorn main:app --host 0.0.0.0 --port $PORT"
#   4. Fly.io: fly launch
#   5. Railway: Connect repo, it auto-detects Python
#
# Environment variables:
#   PORT          - Server port (default: 8000)
#   SEED_DIR      - Directory with seed-data.json (default: /app)
#   SEED_PATH     - Full path to seed file (overrides SEED_DIR)
#   API_KEY       - If set, requires X-API-Key header on all requests

## Endpoints

### ShieldView
| Method | Path | Description |
|--------|------|-------------|
| GET | /v1/status | API health + data counts |
| GET | /v1/dashboard | Unified dashboard stats |
| GET | /v1/executive | Executive summary for leadership |
| GET | /v1/trends | Trend data (7d/30d/90d) |
| GET | /v1/assets | List all assets (filterable) |
| GET | /v1/assets/:hostname | Single asset detail |
| GET | /v1/cves | List all CVEs (filterable) |
| GET | /v1/cves/:cve_id | Single CVE with affected assets |
| GET | /v1/findings | List findings (filterable, groupable) |
| GET | /v1/teams | List teams |
| GET | /v1/teams/:slug | Team detail with findings |
| GET | /v1/recently-fixed | Recently fixed CVEs |

### RemFlow
| Method | Path | Description |
|--------|------|-------------|
| GET | /v1/remflow/dashboard | RemFlow-specific dashboard |
| GET | /v1/remediations | List remediations |
| GET | /v1/remediations/:id | Single remediation detail |
| GET | /v1/deployments | List deployments |
| GET | /v1/deployments/:id | Single deployment detail |
| GET | /v1/endpoint-checks | Endpoint health checks |
| GET | /v1/gpo | GPO compliance policies |
| GET | /v1/health | Health summary |
| GET | /v1/software-versions | Software version compliance |

### Webhooks / Actions
| Method | Path | Description |
|--------|------|-------------|
| POST | /v1/webhooks/remediate | Create remediation from ShieldView |
| POST | /v1/webhooks/deploy | Trigger deployment from remediation |
| POST | /v1/webhooks/import | Trigger data import via connectors |
| POST | /v1/reload | Reload seed data from disk |

### Cross-tool localStorage (client-side)
The three HTML tools continue to communicate via localStorage at mrdchiang.github.io:
- `security-tools:remediation-queue` — ShieldView → RemFlow
- `security-tools:validated-remediations` — RemFlow → TheValidator
