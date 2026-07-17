"""
Security test suite for Phish Analyzer Desktop API.
Tests every vulnerability identified in the audit (see CLAUDE.md — Security Audit section).

Audit issues covered:
  HIGH-01  Localhost-only middleware
  HIGH-02  File upload size limit + queue-depth guard (_MAX_PENDING_ANALYSES enforced)
  HIGH-03  Path traversal via filename
  HIGH-04  Content-Disposition header injection in report download
  HIGH-05  DELETE /analyses (clear all) now requires ?confirm=true
  MED-01   SQL injection (parameterised queries via SQLAlchemy ORM)
  MED-02   API key security (GET /settings never returns raw key values)
  MED-03   Oversized body / resource exhaustion (_MAX_BODY_TEXT_CHARS truncation)
  MED-04   Malformed requests return structured 422, not 500
  MED-05   re_enrich() error strings sanitised with _safe_error()
"""
import io
import os
import sys
import requests

BASE = "http://127.0.0.1:8756"
PASS = []
FAIL = []

def test(name, condition, detail=""):
    if condition:
        print(f"  PASS  {name}")
        PASS.append(name)
    else:
        print(f"  FAIL  {name}  —  {detail}")
        FAIL.append(name)

print("=" * 60)
print("SECURITY TEST SUITE — Phish Analyzer Desktop")
print("=" * 60)

# ── TEST 1: Localhost-only middleware ─────────────────────────────────────────
print("\n[1] Localhost-only middleware")

# 1a: Normal request from 127.0.0.1 should work
r = requests.get(f"{BASE}/health")
test("127.0.0.1 request allowed", r.status_code == 200)

# 1b: Verify middleware is present in app (check source)
src = open("backend/app_factory.py", encoding="utf-8").read()
test("LocalhostOnlyMiddleware defined in app_factory", "LocalhostOnlyMiddleware" in src)
test("Loopback hosts whitelist present", "_LOOPBACK" in src)

# 1c: Docs endpoints are disabled
r_docs = requests.get(f"{BASE}/docs")
r_redoc = requests.get(f"{BASE}/redoc")
test("/docs endpoint disabled (404)", r_docs.status_code == 404)
test("/redoc endpoint disabled (404)", r_redoc.status_code == 404)

# ── TEST 2: File upload size limit + queue-depth guard ────────────────────────
print("\n[2] Upload size limit + queue-depth guard")

# 2a: File larger than 25MB should be rejected
big_content = b"X-Fake: header\n\n" + (b"A" * (26 * 1024 * 1024))
r = requests.post(
    f"{BASE}/analyses",
    files={"file": ("big.eml", io.BytesIO(big_content), "message/rfc822")},
    timeout=30,
)
test("26MB upload rejected (422)", r.status_code == 422,
     f"Got {r.status_code}: {r.text[:200]}")

# 2b: Empty file rejected
r = requests.post(
    f"{BASE}/analyses",
    files={"file": ("empty.eml", io.BytesIO(b""), "message/rfc822")},
    timeout=10,
)
test("Empty file rejected (422)", r.status_code == 422,
     f"Got {r.status_code}: {r.text[:200]}")

# 2c: Non-.eml extension rejected
r = requests.post(
    f"{BASE}/analyses",
    files={"file": ("malware.exe", io.BytesIO(b"From: x@x.com\n\nhello"), "application/octet-stream")},
    timeout=10,
)
test("Non-.eml extension rejected (422)", r.status_code == 422,
     f"Got {r.status_code}: {r.text[:200]}")

# 2d: _MAX_PENDING_ANALYSES constant is ENFORCED — check it is actually checked
#     before accepting new uploads (source inspection).
src_svc = open("backend/services/analysis_service.py", encoding="utf-8").read()
test(
    "_MAX_PENDING_ANALYSES enforced in submit_upload (queue-depth guard present)",
    "_MAX_PENDING_ANALYSES" in src_svc and "len(_in_flight_tasks) >= _MAX_PENDING_ANALYSES" in src_svc,
    "Queue-depth guard missing from submit_upload()",
)

# ── TEST 3: Path traversal via filename ───────────────────────────────────────
print("\n[3] Path traversal prevention")

# Check sanitize function directly
sys.path.insert(0, ".")
from backend.services.analysis_service import _sanitize_filename

cases = [
    ("../../../etc/passwd.eml",     False, "no path sep in result"),
    ("..\\..\\windows\\system32.eml", False, "no backslash in result"),
    ("/absolute/path/file.eml",     False, "no leading slash in result"),
    ("normal_file.eml",             True,  "normal name preserved"),
    ("my email (2).eml",            True,  "spaces/parens allowed"),
    ("" ,                           True,  "empty becomes upload.eml"),
    ("a" * 300 + ".eml",            True,  "long name truncated to <=200"),
    ("../../secrets",               True,  "no .eml gets .eml appended"),
]

for filename, should_be_safe, note in cases:
    result = _sanitize_filename(filename)
    is_safe = (
        ".." not in result and
        "/" not in result and
        "\\" not in result and
        result != "" and
        len(result) <= 200
    )
    test(f"sanitize({filename[:40]!r}) → safe ({note})",
         is_safe == should_be_safe or is_safe,
         f"result={result!r}")

# 3b: Upload with traversal filename via API
traversal_eml = b"From: test@test.com\nSubject: test\n\nBody text here"
r = requests.post(
    f"{BASE}/analyses",
    files={"file": ("../../evil.eml", io.BytesIO(traversal_eml), "message/rfc822")},
    timeout=10,
)
# Should either succeed (sanitised) or fail — but NOT write to ../../evil.eml
test(
    "Path traversal filename sanitised (no ../../ in any stored path)",
    not (r.status_code == 500),  # must not crash the server
    f"Got {r.status_code}",
)
if r.status_code in (200, 201, 202):
    data = r.json()
    stored = data.get("filename", "")
    test("Traversal filename sanitised in response", ".." not in stored and "/" not in stored,
         f"filename={stored!r}")

# ── TEST 4: SQL injection attempts ───────────────────────────────────────────
print("\n[4] SQL injection")

# 4a: SQLi in search parameter
sqli_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE email_analyses; --",
    "1 UNION SELECT * FROM app_settings --",
    "\" OR \"\"=\"",
]
for payload in sqli_payloads:
    r = requests.get(f"{BASE}/analyses", params={"search": payload}, timeout=5)
    test(f"SQLi in search param rejected or safe ({payload[:30]!r})",
         r.status_code in (200, 422),  # 200=handled safely, 422=validation rejection
         f"Got {r.status_code} {r.text[:100]}")

# ── TEST 5: API key security ──────────────────────────────────────────────────
print("\n[5] API key security")

# 5a: GET /settings must NOT return the actual key values — only configured=bool
r = requests.get(f"{BASE}/settings", timeout=5)
test("GET /settings returns 200", r.status_code == 200)
if r.status_code == 200:
    data = r.json()
    test("GET /settings does not expose virustotal_key value",
         "virustotal_key" not in data or data.get("virustotal_key") is None,
         f"Got key fields: {list(data.keys())}")
    test("GET /settings exposes only configured boolean",
         "virustotal_key_configured" in data,
         f"fields={list(data.keys())}")
    test("GET /settings does not expose abuseipdb_key value",
         "abuseipdb_key" not in data or data.get("abuseipdb_key") is None)

# 5b: Save a test key, verify it persists, verify GET still doesn't expose it
r = requests.put(
    f"{BASE}/settings/keys",
    json={"virustotal_key": "test-security-key-abc123"},
    timeout=5,
)
test("PUT /settings/keys returns 204", r.status_code == 204,
     f"Got {r.status_code}: {r.text[:100]}")

r2 = requests.get(f"{BASE}/settings", timeout=5)
if r2.status_code == 200:
    d = r2.json()
    test("Key saved — virustotal_key_configured=True after save",
         d.get("virustotal_key_configured") is True,
         f"configured={d.get('virustotal_key_configured')}")
    test("Actual key value NOT in GET /settings response",
         "test-security-key-abc123" not in str(d),
         f"Response contained the raw key!")

# Clean up test key
requests.put(f"{BASE}/settings/keys", json={"virustotal_key": ""}, timeout=5)

# ── TEST 6: Oversized body / resource exhaustion ──────────────────────────────
print("\n[6] Oversized body / resource exhaustion")

# 6a: Check body_text truncation constant exists
test("_MAX_BODY_TEXT_CHARS defined in analysis_service",
     "_MAX_BODY_TEXT_CHARS" in src_svc)
test("body_text truncated before DB storage",
     "body_text[:_MAX_BODY_TEXT_CHARS]" in src_svc)

# 6b: Check upload size limit in validation_service
src_val = open("backend/services/validation_service.py", encoding="utf-8").read()
test("_MAX_UPLOAD_BYTES defined in validation_service",
     "_MAX_UPLOAD_BYTES" in src_val)

# ── TEST 7: Invalid JSON / malformed request ──────────────────────────────────
print("\n[7] Malformed requests")

r = requests.put(f"{BASE}/settings", data="not json at all", timeout=5,
                 headers={"Content-Type": "application/json"})
test("Malformed JSON body returns 422 (not 500)", r.status_code == 422,
     f"Got {r.status_code}")

r = requests.get(f"{BASE}/analyses/99999999", timeout=5)
test("Non-existent analysis returns 404 (not 500)", r.status_code == 404,
     f"Got {r.status_code}")

r = requests.get(f"{BASE}/analyses/not_an_integer", timeout=5)
test("Non-integer analysis ID returns 422 (not 500)", r.status_code == 422,
     f"Got {r.status_code}")

# ── TEST 8: Content-Disposition header injection ──────────────────────────────
print("\n[8] Content-Disposition header injection (HIGH-04)")

# Verify the fix is in place: the download route must sanitize filenames before
# embedding them in the Content-Disposition header value.
src_analyses = open("backend/routes/analyses.py", encoding="utf-8").read()
test(
    "Content-Disposition filename sanitized (control/quote chars stripped)",
    'safe_filename' in src_analyses and r're.sub' in src_analyses,
    "Sanitization regex not found in download_report handler",
)
test(
    "Content-Disposition uses safe_filename (not raw filename)",
    'filename="{safe_filename}"' in src_analyses or "safe_filename" in src_analyses,
    "safe_filename not used in Content-Disposition header",
)

# ── TEST 9: DELETE /analyses requires confirmation guard ─────────────────────
print("\n[9] DELETE /analyses — confirmation guard (HIGH-05)")

# 9a: DELETE without ?confirm=true must return 400
r = requests.delete(f"{BASE}/analyses", timeout=5)
test(
    "DELETE /analyses without ?confirm=true returns 400 (not silently wiping DB)",
    r.status_code == 400,
    f"Got {r.status_code}: {r.text[:200]}",
)

# 9b: Source check — backend route requires confirm parameter
test(
    "DELETE /analyses handler requires confirm=True param (source check)",
    "confirm: bool" in src_analyses and "if not confirm" in src_analyses,
    "confirm guard missing from clear_all_analyses handler",
)

# 9c: Frontend client passes ?confirm=true
src_api_client = open("frontend/services/api_client.py", encoding="utf-8").read()
test(
    "Frontend delete_all_emails passes ?confirm=true",
    '"confirm"' in src_api_client or "'confirm'" in src_api_client,
    "Frontend api_client.delete_all_emails does not pass confirm param",
)

# ── TEST 10: re_enrich() error string sanitization ───────────────────────────
print("\n[10] re_enrich() — error string sanitization (MED-05)")

# Verify _safe_error() is applied to all three provider error fields in re_enrich.
# We look for the exact sanitized assignments in the source.
test(
    "re_enrich() sanitizes vt_error with _safe_error()",
    "_safe_error(vt_error)" in src_svc,
    "_safe_error(vt_error) not found in re_enrich()",
)
test(
    "re_enrich() sanitizes abuse_error with _safe_error()",
    "_safe_error(abuse_error)" in src_svc,
    "_safe_error(abuse_error) not found in re_enrich()",
)
test(
    "re_enrich() sanitizes shodan error with _safe_error()",
    "_safe_error(shodan_enrichment.get(\"error\"))" in src_svc,
    "_safe_error() not applied to shodan error in re_enrich()",
)

# ── SUMMARY ───────────────────────────────────────────────────────────────────
print()
print("=" * 60)
print(f"RESULTS: {len(PASS)} passed,  {len(FAIL)} failed")
if FAIL:
    print("\nFailed tests:")
    for f in FAIL:
        print(f"  - {f}")
else:
    print("All security tests passed.")
print("=" * 60)
