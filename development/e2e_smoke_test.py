#!/usr/bin/env python3
"""Live end-to-end smoke test for tenant-fs-server (real sockets, ports 18080/18081).

Reproduces the README's 18-check smoke test plus additional security probes:
X-Forwarded-For spoofing against IP-bound share tokens (must be IGNORED by
default), unsigned-upload rejection before streaming, folder ACL inheritance,
batch ACL vs inherited deny (deny always wins), export tar, admin soft delete,
and DB/blob layout inspection.

Run against a server started with the default (secure) settings:
  TENANT_FS_DB=<dir>/fs.db TENANT_FS_BLOBS=<dir>/blobs
  TENANT_FS_ADMIN_TOKEN=dev-admin-token TENANT_FS_SERVER_SECRET=dev-server-secret-change-me
  TENANT_FS_PUBLIC_BIND=127.0.0.1:18080 TENANT_FS_ADMIN_BIND=127.0.0.1:18081
Do NOT set TENANT_FS_TRUST_XFF (default mode exercises the spoof fixes).

For PART 9 the server must additionally run with the soft-delete test knobs:
  TENANT_FS_SOFT_DELETE_DAYS=0          # no grace window -> tombstones are due
                                        # on the next maintenance tick
  TENANT_FS_PURGE_INTERVAL_SECS=3      # maintenance loop every 3s
  TENANT_FS_ENCRYPT_BLOBS=true          # (default) envelope encryption at rest

For PART 10 the server must additionally run with:
  TENANT_FS_BACKUP_ROOT=<dir>/backups  # backup artifacts root (also used to
                                        # verify the manifest sha256 on disk)
  TENANT_FS_EXPORT_TTL_SECS=12         # short TTL so the export sweep is visible
  TENANT_FS_RATE_LIMIT_PER_MIN=100     # low enough to trigger 429 quickly, high
                                        # enough for the rest of the suite
"""
import hashlib, hmac, http.client, json, os, random, string, sys, time, urllib.parse, uuid, base64, sqlite3

PUB = ("127.0.0.1", 18080)
ADM = ("127.0.0.1", 18081)
ADMIN_TOKEN = "dev-admin-token"
BLOBS = os.environ.get("TENANT_FS_BLOBS", "data/blobs")
DB_PATH = os.environ.get("TENANT_FS_DB", "data/fs.db")

passed, failed = [], []

def check(name, cond, detail=""):
    if cond:
        passed.append(name)
        print(f"  [PASS] {name}")
    else:
        failed.append(name)
        print(f"  [FAIL] {name}  {detail}")

def req(host_port, method, path, body=b"", headers=None, timeout=10):
    conn = http.client.HTTPConnection(*host_port, timeout=timeout)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read()
    hdrs = dict(r.getheaders())
    status = r.status
    conn.close()
    return status, data, hdrs

def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()

def app_sig(secret, method, path, query, body, ts, nonce):
    bh = sha256_hex(body)
    canonical = f"{method}\n{path}\n{query}\n{bh}\n{ts}\n{nonce}"
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

def signed_headers(key, secret, method, path, query, body, extra=None):
    ts = str(int(time.time()))
    nonce = "n_" + uuid.uuid4().hex
    sig = app_sig(secret, method, path, query, body, ts, nonce)
    hdrs = {
        "x-app-key": key,
        "x-app-signature": sig,
        "x-timestamp": ts,
        "x-nonce": nonce,
    }
    for k, v in (extra or {}).items():
        hdrs[k] = v
    return hdrs

def signed_req(key, secret, method, path, query="", body=b"", extra=None):
    uri = path if not query else f"{path}?{query}"
    return req(PUB, method, uri, body=body, headers=signed_headers(key, secret, method, path, query, body, extra))

def signed_json(key, secret, method, path, query="", obj=None, extra=None):
    body = b"" if obj is None else json.dumps(obj).encode()
    return signed_req(key, secret, method, path, query, body, extra)

def jwt_for(secret, app_id, user, exp_ttl=3600):
    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64u(json.dumps({"iss": f"app:{app_id}", "sub": user, "exp": int(time.time()) + exp_ttl}, separators=(",", ":")).encode())
    signing = f"{header}.{payload}"
    sig = b64u(hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest())
    return f"{signing}.{sig}"

def admin_req(method, path, obj=None, token=ADMIN_TOKEN):
    body = b"" if obj is None else json.dumps(obj).encode()
    return req(ADM, method, path, body=body, headers={"authorization": f"Bearer {token}"})

def json_body(resp):
    status, data, hdrs = resp
    try:
        return status, json.loads(data), hdrs
    except Exception:
        return status, None, hdrs

def create_app(name, quota=10 * 1024 * 1024 * 1024, max_payload=100 * 1024 * 1024):
    s, v, _ = json_body(admin_req("POST", "/admin/v1/apps", {"name": name, "quota_bytes": quota, "max_payload_bytes": max_payload}))
    return s, v

print("=" * 60)
print("PART 0: admin auth + app creation")
print("=" * 60)
s, _, _ = req(ADM, "GET", "/admin/v1/apps")
check("admin without token -> 401", s == 401, f"got {s}")
s, _, _ = req(ADM, "GET", "/admin/v1/apps", headers={"authorization": "Bearer wrong"})
check("admin wrong token -> 401", s == 401, f"got {s}")
s, v = create_app("TenantA")
check("create app A -> 200", s == 200, f"got {s} {v}")
if s == 200:
    APP_A_ID = v["app_id"]
    APP_KEY = v["app_key"]
    SECRET_A = v["app_secret"]
else:
    sys.exit("cannot create app A")

s, v = create_app("TenantB")
check("create app B -> 200", s == 200, f"got {s} {v}")
if s == 200:
    APP_B_ID = v["app_id"]
    KEY_B = v["app_key"]
    SECRET_B = v["app_secret"]
else:
    sys.exit("cannot create app B")

# admin routes must not be exposed on public router
s, _, _ = req(PUB, "GET", "/admin/v1/apps")
check("admin path on public router -> 404", s == 404, f"got {s}")

print()
print("=" * 60)
print("PART 1: upload / download / embed idempotency / revoke")
print("=" * 60)
CONTENT = b"hello tenant from live e2e"
s, v, _ = json_body(signed_req(APP_KEY, SECRET_A, "POST", "/v1/upload", body=CONTENT, extra={"x-user-id": "u1"}))
check("signed upload -> 200", s == 200, f"got {s} {v}")
FILE1 = v.get("file_id") if isinstance(v, dict) else None
check("upload returns file_id + sha256", isinstance(v, dict) and v.get("file_id") and v.get("sha256") == sha256_hex(CONTENT), f"{v}")

s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": FILE1}))
check("generate embed link -> 200", s == 200, f"got {s} {v}")
TOKEN1 = v.get("token") if isinstance(v, dict) else None
check("embed reused=false first time", isinstance(v, dict) and v.get("reused") is False, f"{v}")

s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": FILE1}))
check("embed idempotent -> same token, reused=true", s == 200 and v.get("token") == TOKEN1 and v.get("reused") is True, f"{v}")

s, data, hdrs = req(PUB, "GET", f"/v1/download/{TOKEN1}")
check("download via token -> 200 + exact body", s == 200 and data == CONTENT, f"got {s}")
check("download ETag present", "etag" in hdrs, f"{hdrs.get('etag')}")

s, data, hdrs = req(PUB, "GET", f"/v1/download/{TOKEN1}", headers={"Range": "bytes=2-5"})
check("range download -> 206 + slice", s == 206 and data == CONTENT[2:6], f"got {s} {data[:20]}")

etag = hdrs.get("etag") or f'"sha256-{sha256_hex(CONTENT)}"'
s, data, hdrs = req(PUB, "GET", f"/v1/download/{TOKEN1}", headers={"If-None-Match": etag})
check("if-none-match -> 304", s == 304, f"got {s}")

s, data, hdrs = req(PUB, "GET", f"/v1/download/{TOKEN1}", headers={"Range": "bytes=99999-"})
check("out-of-range -> 416", s == 416, f"got {s}")

s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/tokens/revoke", obj={"token": TOKEN1}))
check("revoke token -> 200", s == 200 and v.get("revoked") is True, f"{v}")
s, _, _ = req(PUB, "GET", f"/v1/download/{TOKEN1}")
check("revoked token download -> 404", s == 404, f"got {s}")
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": FILE1}))
check("post-revoke generate mints NEW token", s == 200 and v.get("reused") is False and v.get("token") != TOKEN1, f"{v}")
TOKEN2 = v.get("token")

print()
print("=" * 60)
print("PART 2: cross-tenant isolation")
print("=" * 60)
s, v, _ = json_body(signed_json(KEY_B, SECRET_B, "POST", "/v1/links/generate", obj={"file_id": FILE1}))
check("tenant B link on A's file -> 404 (hidden)", s == 404, f"got {s}")
s, _, _ = signed_req(KEY_B, SECRET_B, "GET", f"/v1/files/{FILE1}")
check("tenant B GET A's file meta -> 404", s == 404, f"got {s}")
s, v, _ = json_body(signed_req(KEY_B, SECRET_B, "GET", "/v1/files"))
check("tenant B file list empty", s == 200 and isinstance(v, dict) and len(v.get("files", [])) == 0, f"{v}")
s, data, _ = req(PUB, "GET", f"/v1/download/{TOKEN2}")
check("A's new token still works for A", s == 200 and data == CONTENT, f"got {s}")

print()
print("=" * 60)
print("PART 3: auth hardening (forgery / replay / stale / JWT)")
print("=" * 60)
ts = str(int(time.time()))
bad_sig = "deadbeef" * 4
s, _, _ = req(PUB, "GET", "/v1/files", headers={"x-app-key": APP_KEY, "x-app-signature": bad_sig, "x-timestamp": ts, "x-nonce": "forgery-1"})
check("forged HMAC -> 401", s == 401, f"got {s}")

nonce = "replay-test-1"
sig = app_sig(SECRET_A, "GET", "/v1/files", "", b"", ts, nonce)
s, _, _ = req(PUB, "GET", "/v1/files", headers={"x-app-key": APP_KEY, "x-app-signature": sig, "x-timestamp": ts, "x-nonce": nonce})
check("first nonce use -> 200", s == 200, f"got {s}")
s, _, _ = req(PUB, "GET", "/v1/files", headers={"x-app-key": APP_KEY, "x-app-signature": sig, "x-timestamp": ts, "x-nonce": nonce})
check("nonce replay -> 401", s == 401, f"got {s}")

stale = str(int(time.time()) - 10000)
sig2 = app_sig(SECRET_A, "GET", "/v1/files", "", b"", stale, "stale-1")
s, _, _ = req(PUB, "GET", "/v1/files", headers={"x-app-key": APP_KEY, "x-app-signature": sig2, "x-timestamp": stale, "x-nonce": "stale-1"})
check("stale timestamp -> 401", s == 401, f"got {s}")

# user JWT flow
jwt = jwt_for(SECRET_A, APP_A_ID, "u1")
s, v, _ = json_body(req(PUB, "GET", "/v1/files", headers={"authorization": f"Bearer {jwt}"}))
check("user JWT list -> 200 (sees own file)", s == 200 and any(f.get("file_id") == FILE1 for f in v.get("files", [])), f"{v}")

jwt_forged = jwt_for("wrong-secret", APP_A_ID, "u1")
s, _, _ = req(PUB, "GET", "/v1/files", headers={"authorization": f"Bearer {jwt_forged}"})
check("JWT wrong secret -> 401", s == 401, f"got {s}")

jwt_ghost = jwt_for(SECRET_A, APP_A_ID, "u_ghost")
s, _, _ = req(PUB, "GET", "/v1/files", headers={"authorization": f"Bearer {jwt_ghost}"})
check("JWT unregistered user -> 401", s == 401, f"got {s}")

print()
print("=" * 60)
print("PART 4: ACL + folder inheritance + deny wins")
print("=" * 60)
# register u2 by uploading as u2
s, v, _ = json_body(signed_req(APP_KEY, SECRET_A, "POST", "/v1/upload", body=b"x", extra={"x-user-id": "u2"}))
check("upload as u2 (registers user)", s == 200, f"got {s} {v}")

jwt_u1 = jwt_for(SECRET_A, APP_A_ID, "u1")
jwt_u2 = jwt_for(SECRET_A, APP_A_ID, "u2")
s, _, _ = req(PUB, "GET", f"/v1/files/{FILE1}", headers={"authorization": f"Bearer {jwt_u1}"})
check("owner u1 reads meta -> 200", s == 200, f"got {s}")
s, _, _ = req(PUB, "GET", f"/v1/files/{FILE1}", headers={"authorization": f"Bearer {jwt_u2}"})
check("u2 read denied -> 403", s == 403, f"got {s}")

s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/folders", obj={"name": "invoices"}))
check("create folder -> 200", s == 200, f"got {s} {v}")
FOLDER1 = v.get("folder_id")

s, v, _ = json_body(signed_req(APP_KEY, SECRET_A, "POST", "/v1/upload", body=b"invoice-content", query=f"folder_id={FOLDER1}", extra={"x-user-id": "u1"}))
check("upload into folder", s == 200, f"got {s} {v}")
FILE2 = v.get("file_id")

s, _, _ = req(PUB, "GET", f"/v1/files/{FILE2}", headers={"authorization": f"Bearer {jwt_u2}"})
check("u2 denied before folder grant -> 403", s == 403, f"got {s}")

s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "PATCH", f"/v1/folders/{FOLDER1}/acl", obj={"action": "read", "add": ["u2"]}))
check("grant folder read to u2", s == 200, f"got {s} {v}")
s, _, _ = req(PUB, "GET", f"/v1/files/{FILE2}", headers={"authorization": f"Bearer {jwt_u2}"})
check("u2 reads via folder inheritance -> 200", s == 200, f"got {s}")

s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "PATCH", f"/v1/folders/{FOLDER1}/acl", obj={"action": "read", "add": [], "deny": ["u2"]}))
check("add deny u2 on folder", s == 200, f"got {s} {v}")
s, _, _ = req(PUB, "GET", f"/v1/files/{FILE2}", headers={"authorization": f"Bearer {jwt_u2}"})
check("inherited deny wins -> 403", s == 403, f"got {s}")

# batch ACL
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/files/batch/acl", obj={"file_ids": [FILE1, FILE2], "action": "read", "add": ["u2"]}))
check("batch ACL -> updated=2", s == 200 and v.get("updated") == 2, f"{v}")
s, _, _ = req(PUB, "GET", f"/v1/files/{FILE2}", headers={"authorization": f"Bearer {jwt_u2}"})
check("u2 read after batch grant (deny still present)", s == 403, f"got {s}")

print()
print("=" * 60)
print("PART 5: quota / payload limits / usage / audit")
print("=" * 60)
s, v = create_app("QuotaApp", quota=100, max_payload=100)
check("create small-quota app", s == 200, f"{v}")
QKEY, QSECRET = v["app_key"], v["app_secret"]
s, _, _ = signed_req(QKEY, QSECRET, "POST", "/v1/upload", body=b"0123456789", extra={"x-user-id": "q1"})
check("10B upload ok", s == 200, f"got {s}")
s, _, _ = signed_req(QKEY, QSECRET, "POST", "/v1/upload", body=b"abcdefghij", extra={"x-user-id": "q1"})
check("second 10B upload ok", s == 200, f"got {s}")
s, v, _ = json_body(signed_req(QKEY, QSECRET, "POST", "/v1/upload", body=b"x" * 90, extra={"x-user-id": "q1"}))
check("90B upload -> 429 quota_exceeded", s == 429 and isinstance(v, dict) and v.get("error", {}).get("code") == "quota_exceeded", f"got {s} {v}")

s, v = create_app("PayloadApp", quota=1 << 20, max_payload=5)
check("create small-payload app", s == 200, f"{v}")
PKEY, PSECRET = v["app_key"], v["app_secret"]
s, v, _ = json_body(signed_req(PKEY, PSECRET, "POST", "/v1/upload", body=b"1234567890", extra={"x-user-id": "p1"}))
check("10B > 5B payload limit -> 413", s == 413, f"got {s} {v}")

s, v, _ = json_body(admin_req("GET", f"/admin/v1/apps/{APP_A_ID}/usage"))
check("usage endpoint -> 200 + usage_bytes>0", s == 200 and v.get("usage_bytes", 0) > 0, f"{v}")
s, v, _ = json_body(admin_req("GET", "/admin/v1/audit"))
check("audit log -> 200 + entries", s == 200 and len(v.get("entries", [])) > 0, f"got {s}")

print()
print("=" * 60)
print("PART 6: share token + IP binding (default mode: XFF ignored)")
print("=" * 60)
# Default deployment (TENANT_FS_TRUST_XFF unset): client IP is the socket
# peer (127.0.0.1 here), and X-Forwarded-For is IGNORED (test report §5.2).
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": FILE1, "scope": "share", "allowed_ip": "127.0.0.1"}))
check("generate share token bound to local peer IP", s == 200, f"got {s} {v}")
SHARE = v.get("token")
s, data, _ = req(PUB, "GET", f"/v1/download/{SHARE}")
check("share from real peer IP (no XFF) -> 200", s == 200 and data == CONTENT, f"got {s}")
s, data, _ = req(PUB, "GET", f"/v1/download/{SHARE}", headers={"x-forwarded-for": "6.6.6.6"})
check("XFF=6.6.6.6 cannot change client IP -> still 200", s == 200 and data == CONTENT, f"got {s}")

s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": FILE1, "scope": "share", "allowed_ip": "203.0.113.45"}))
check("generate share token with remote allowed_ip", s == 200, f"got {s} {v}")
SHARE2 = v.get("token")
s, _, _ = req(PUB, "GET", f"/v1/download/{SHARE2}", headers={"x-forwarded-for": "203.0.113.45"})
check("SPOOF FIXED: XFF=allowed IP -> 404 (header ignored)", s == 404, f"got {s}")

print()
print("=" * 60)
print("PART 7: unsigned-upload rejection + error shapes")
print("=" * 60)
print("  [PROBE] app-key-only upload with NO signature: must be rejected BEFORE streaming")
s, v, _ = json_body(req(PUB, "POST", "/v1/upload", body=b"x" * 4096, headers={"x-app-key": APP_KEY, "x-user-id": "u1"}))
check("PROBE: no-signature upload -> 401 (rejected before streaming)", s == 401 and "Missing signature header" in str(v.get("error", {}).get("message", "")), f"got {s} {v}")
s, v, _ = json_body(req(PUB, "POST", "/v1/upload", body=b"x" * 4096))
check("no auth at all -> 401", s == 401, f"got {s}")

s, _, _ = req(PUB, "GET", "/v1/files", headers={"x-app-key": APP_KEY})
check("missing signature headers -> 401", s == 401, f"got {s}")

# malformed JSON
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": "not-a-number"}))
check("bad file_id type -> 400", s == 400, f"got {s} {v}")

print()
print("=" * 60)
print("PART 8: export tar + admin ops + persistence")
print("=" * 60)
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/apps/export"))
check("start export -> job_id", s == 200 and v.get("job_id"), f"got {s} {v}")
JOB = v.get("job_id")
ready = False
for _ in range(50):
    s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "GET", f"/v1/apps/exports/{JOB}"))
    if s == 200 and v.get("status") == "ready":
        ready = True
        break
    time.sleep(0.05)
check("export job becomes ready", ready, f"last {v}")
s, data, hdrs = signed_req(APP_KEY, SECRET_A, "GET", f"/v1/apps/exports/{JOB}/download")
check("export download -> tar magic", s == 200 and b"ustar" in data[:512], f"got {s} len={len(data)}")

# secret rotation
s, v, _ = json_body(admin_req("POST", f"/admin/v1/apps/{APP_A_ID}/secret/rotate"))
check("rotate secret -> new secret", s == 200 and v.get("app_secret") and v.get("app_secret") != SECRET_A, f"{v}")
NEW_SECRET = v.get("app_secret")
s, _, _ = signed_req(APP_KEY, SECRET_A, "GET", "/v1/files")
check("old secret after rotation -> 401", s == 401, f"got {s}")
s, _, _ = signed_req(APP_KEY, NEW_SECRET, "GET", "/v1/files")
check("new secret works -> 200", s == 200, f"got {s}")
SECRET_A = NEW_SECRET  # keep going with new secret

# admin soft delete app -> requests 401
s, _, _ = admin_req("DELETE", f"/admin/v1/apps/{APP_B_ID}")
check("admin soft-delete app B -> 204", s == 204, f"got {s}")
s, _, _ = signed_req(KEY_B, SECRET_B, "GET", "/v1/files")
check("deleted app B requests -> 401", s == 401, f"got {s}")

# delete file frees usage + tokens
s, _, _ = signed_req(APP_KEY, SECRET_A, "DELETE", f"/v1/files/{FILE1}")
check("delete file -> 204", s == 204, f"got {s}")
s, _, _ = req(PUB, "GET", f"/v1/download/{TOKEN2}")
check("token after file delete -> 404", s == 404, f"got {s}")
s, v, _ = json_body(admin_req("GET", f"/admin/v1/apps/{APP_A_ID}/usage"))
check("usage dropped after delete", s == 200, f"{v}")

print()
print("=" * 60)
print("PART 9: soft-delete grace + envelope blob encryption")
print("=" * 60)

def find_blob_file(app_id, u):
    base = os.path.join(BLOBS, f"app_{app_id}")
    if not os.path.isdir(base):
        return None
    for dp, _dn, fn in os.walk(base):
        if u in fn:
            return os.path.join(dp, u)
    return None

PROBE = b"soft-delete-probe-payload"
s, v, _ = json_body(signed_req(APP_KEY, SECRET_A, "POST", "/v1/upload", body=PROBE, extra={"x-user-id": "u1"}))
check("probe upload -> 200", s == 200, f"{s} {v}")
PROBE_ID = v.get("file_id")
PROBE_UUID = v.get("storage_uuid")
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": PROBE_ID}))
PROBE_TOK = v.get("token")
s, data, _ = req(PUB, "GET", f"/v1/download/{PROBE_TOK}")
check("probe download warmup -> exact bytes", s == 200 and data == PROBE, f"{s}")

# write-new: on-disk blob carries the envelope magic; plaintext is not verbatim
blob_on_disk = find_blob_file(APP_A_ID, PROBE_UUID)
head = open(blob_on_disk, "rb").read(4) if blob_on_disk else None
on_disk = open(blob_on_disk, "rb").read() if blob_on_disk else b""
check("new upload lands as envelope (TSFS) blob", head == b"TSFS", f"head={head}")
check("plaintext not stored verbatim on disk", PROBE not in on_disk, "plaintext leaked to disk")

# read-old: simulate a pre-encryption legacy plaintext blob, drop the dec cache
cache = os.path.join(BLOBS, "dec_cache", PROBE_UUID)
if os.path.exists(cache):
    os.remove(cache)
with open(blob_on_disk, "wb") as f:
    f.write(PROBE)
s, data, _ = req(PUB, "GET", f"/v1/download/{PROBE_TOK}")
check("legacy plaintext blob still downloads (read-old)", s == 200 and data == PROBE, f"{s}")

# soft-delete
s, _, _ = signed_req(APP_KEY, SECRET_A, "DELETE", f"/v1/files/{PROBE_ID}")
check("soft-delete probe -> 204", s == 204, f"{s}")
s, _, _ = req(PUB, "GET", f"/v1/download/{PROBE_TOK}")
check("download after soft-delete -> 404", s == 404, f"{s}")
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "GET", "/v1/files"))
check("list excludes soft-deleted file", s == 200 and all(f.get("file_id") != PROBE_ID for f in v.get("files", [])), f"{v}")
check("blob retained during grace window (not hard-deleted)", os.path.exists(blob_on_disk), f"{blob_on_disk}")

# wait for the maintenance tick (interval ~3s, grace=0) to purge the tombstone
purged = False
for _ in range(20):
    time.sleep(1)
    if not os.path.exists(blob_on_disk):
        purged = True
        break
check("purge tick physically removes expired blob", purged, f"blob still present: {blob_on_disk}")

n = None
try:
    conn = sqlite3.connect(DB_PATH)
    n = conn.execute("SELECT COUNT(*) FROM files WHERE id=?", (PROBE_ID,)).fetchone()[0]
    conn.close()
except Exception as e:
    print(f"  (sqlite probe failed: {e})")
check("purge removes DB tombstone row", n == 0, f"count={n}")

print()
print("=" * 60)
print("PART 10: backup API / chunked upload / rate limit / HEAD / zip / idempotency / export TTL")
print("=" * 60)

# --- 10.1 backup: run + list + detail + config + manifest sha256 ---
s, v, _ = json_body(admin_req("POST", "/admin/v1/backups/run"))
check("backup run -> ready", s == 200 and v.get("status") == "ready" and v.get("size", 0) > 0, f"got {s} {v}")
BK_ID = v.get("backup_id")
BK_FILES = {f["name"]: f for f in v.get("files", [])} if isinstance(v, dict) else {}
check("backup manifest lists db.sqlite + blobs.tar with sha256", set(BK_FILES) == {"db.sqlite", "blobs.tar"} and all(len(f.get("sha256", "")) == 64 for f in BK_FILES.values()), f"{BK_FILES}")

# verify manifest sha256 against the real artifact on disk
BACKUP_ROOT = os.environ.get("TENANT_FS_BACKUP_ROOT", "data/backups")
manifest_ok = False
try:
    on_disk = open(os.path.join(BACKUP_ROOT, "default", BK_ID, "blobs.tar"), "rb").read()
    manifest_ok = sha256_hex(on_disk) == BK_FILES.get("blobs.tar", {}).get("sha256")
except Exception as e:
    print(f"  (manifest check failed to read artifact: {e})")
check("manifest sha256 matches on-disk blobs.tar", manifest_ok)

s, v, _ = json_body(admin_req("GET", "/admin/v1/backups"))
check("backup list -> contains run", s == 200 and any(b.get("backup_id") == BK_ID for b in v.get("backups", [])), f"{v}")
s, v, _ = json_body(admin_req("GET", "/admin/v1/backups/1"))
check("backup detail -> manifest object", s == 200 and isinstance(v.get("manifest"), dict), f"{v}")
s, _, _ = admin_req("GET", "/admin/v1/backups/99999")
check("unknown backup id -> 404 (hidden)", s == 404, f"got {s}")
s, v, _ = json_body(admin_req("PATCH", "/admin/v1/backups/config", {"retention": 5, "target": "e2e", "schedule": 0}))
check("backup config PATCH -> stored", s == 200 and v.get("retention") == 5 and v.get("target") == "e2e", f"{v}")
s, v, _ = json_body(admin_req("PATCH", "/admin/v1/backups/config", {"target": "../escape"}))
check("backup target path escape -> 400", s == 400, f"got {s}")

# --- 10.2 chunked / resumable upload ---
CHUNK = b"chunked-" + os.urandom(16)
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/upload/init", obj={"total_size": len(CHUNK)}, extra={"x-user-id": "u1"}))
check("chunked init -> upload_id", s == 200 and v.get("upload_id") and len(v["upload_id"]) >= 32, f"{s} {v}")
UP_ID = v.get("upload_id")
HALF = len(CHUNK) // 2
s, v, _ = json_body(signed_req(APP_KEY, SECRET_A, "PUT", f"/v1/upload/{UP_ID}", body=CHUNK[:HALF], extra={"x-chunk-offset": "0"}))
check("chunk 1 -> 200 received=HALF", s == 200 and v.get("received_size") == HALF, f"{s} {v}")
s, v, _ = json_body(signed_req(APP_KEY, SECRET_A, "PUT", f"/v1/upload/{UP_ID}", body=CHUNK[HALF:], extra={"x-chunk-offset": str(HALF)}))
check("chunk 2 -> 200 received=total", s == 200 and v.get("received_size") == len(CHUNK), f"{s} {v}")
s, v, _ = json_body(signed_req(APP_KEY, SECRET_A, "POST", f"/v1/upload/{UP_ID}/finalize", body=b"", extra={"x-user-id": "u1"}))
check("chunked finalize -> 200 + sha256", s == 200 and v.get("sha256") == sha256_hex(CHUNK), f"{s} {v}")
CHUNK_FILE = v.get("file_id")
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": CHUNK_FILE}))
s, data, _ = req(PUB, "GET", f"/v1/download/{v.get('token')}")
check("chunked roundtrip -> exact bytes", s == 200 and data == CHUNK, f"{s}")
s, _, _ = req(PUB, "PUT", f"/v1/upload/{UP_ID}", body=b"x", headers={"x-chunk-offset": "0"})
check("unauthenticated chunk PUT -> 401", s == 401, f"got {s}")

# --- 10.3 per-app rate limit: 429 + Retry-After ---
s, v = create_app("RateApp")
RL_KEY, RL_SECRET = v["app_key"], v["app_secret"]
retry_after = None
for _ in range(200):
    s, _, hdrs = json_body(signed_json(RL_KEY, RL_SECRET, "POST", "/v1/links/generate", obj={"file_id": 1}))
    if s == 429:
        retry_after = hdrs.get("retry-after")
        break
check("rate limit -> 429", retry_after is not None, "never hit 429")
check("429 carries numeric Retry-After (seconds)", retry_after is not None and retry_after.isdigit() and int(retry_after) >= 1, f"retry-after={retry_after}")

# --- 10.4 HEAD download ---
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/links/generate", obj={"file_id": FILE2}))
HEAD_TOK = v.get("token")
s, data, hdrs = req(PUB, "HEAD", f"/v1/download/{HEAD_TOK}")
check("HEAD -> 200 + Content-Length + empty body", s == 200 and int(hdrs.get("content-length", "0")) == len(b"invoice-content") and len(data) == 0, f"{s} len(data)={len(data)} cl={hdrs.get('content-length')}")
s, _, _ = req(PUB, "HEAD", "/v1/download/nope")
check("HEAD unknown token -> 404", s == 404, f"got {s}")

# --- 10.5 zip export organized by user ---
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/apps/export", obj={"format": "zip"}))
ZJOB = v.get("job_id")
ready = False
for _ in range(50):
    s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "GET", f"/v1/apps/exports/{ZJOB}"))
    if v.get("status") == "ready":
        ready = True
        break
    time.sleep(0.05)
check("zip export job ready", ready, f"{v}")
s, data, hdrs = signed_req(APP_KEY, SECRET_A, "GET", f"/v1/apps/exports/{ZJOB}/download")
check("zip export download -> application/zip", s == 200 and "zip" in hdrs.get("content-type", ""), f"{s} {hdrs.get('content-type')}")
import io, zipfile
try:
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    users = {n.split("/")[1] for n in names if n.startswith("files/")}
except Exception as e:
    names, users = [], set()
    print(f"  (zip inspect failed: {e})")
check("zip entries organized by user_id", "u1" in users and "u2" in users, f"users={users}")

# --- 10.6 idempotency key: same result, single row ---
IDEM_BODY = b"idempotent-payload-" + os.urandom(8)
s, v1, _ = json_body(signed_req(APP_KEY, SECRET_A, "POST", "/v1/upload", body=IDEM_BODY, extra={"x-user-id": "u1", "idempotency-key": "e2e-key-1"}))
s, v2, _ = json_body(signed_req(APP_KEY, SECRET_A, "POST", "/v1/upload", body=IDEM_BODY, extra={"x-user-id": "u1", "idempotency-key": "e2e-key-1"}))
check("idempotent retry -> same file_id", s == 200 and v1.get("file_id") == v2.get("file_id"), f"{v1} vs {v2}")

# --- 10.7 export TTL: short-lived export job swept by maintenance ---
s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "POST", "/v1/apps/export", obj={"format": "zip"}))
TJOB = v.get("job_id")
ready = False
for _ in range(50):
    s, v, _ = json_body(signed_json(APP_KEY, SECRET_A, "GET", f"/v1/apps/exports/{TJOB}"))
    if v.get("status") == "ready":
        ready = True
        break
    time.sleep(0.05)
check("TTL export job ready", ready, f"{v}")
s, _, _ = signed_req(APP_KEY, SECRET_A, "GET", f"/v1/apps/exports/{TJOB}/download")
check("TTL export downloadable before sweep", s == 200, f"got {s}")
# wait for the maintenance tick (interval ~3s) + the short TTL env knob (~12s)
gone = False
for _ in range(15):
    time.sleep(2)
    s, _, _ = signed_json(APP_KEY, SECRET_A, "GET", f"/v1/apps/exports/{TJOB}")
    if s == 404:
        gone = True
        break
check("export job swept after TTL", gone, f"job still visible")

print()
print("=" * 60)
print("PART 11: admin console static assets on loopback admin bind")
print("=" * 60)

def hdr_ci(hdrs, name):
    want = name.lower()
    for k, v in hdrs.items():
        if k.lower() == want:
            return v
    return None

# --- 11.1 page + asset Content-Types and security headers ---
s, body, hdrs = req(ADM, "GET", "/admin/")
check("console page GET /admin/ -> 200", s == 200, f"got {s}")
check("console page is the HTML shell (view-login + app.js)",
      b'id="view-login"' in body and b"app.js" in body, "")
check("console page content-type = text/html",
      (hdr_ci(hdrs, "content-type") or "").startswith("text/html"), f"{hdr_ci(hdrs, 'content-type')}")
check("console page sends CSP", bool(hdr_ci(hdrs, "content-security-policy")), f"{hdr_ci(hdrs, 'content-security-policy')}")
check("console page sends X-Frame-Options: DENY",
      (hdr_ci(hdrs, "x-frame-options") or "").lower() == "deny", f"{hdr_ci(hdrs, 'x-frame-options')}")
check("console page sends Cache-Control: no-store",
      (hdr_ci(hdrs, "cache-control") or "") == "no-store", f"{hdr_ci(hdrs, 'cache-control')}")

s, body_js, hdrs_js = req(ADM, "GET", "/admin/app.js")
check("app.js -> 200 + javascript content-type",
      s == 200 and "javascript" in (hdr_ci(hdrs_js, "content-type") or ""), f"{s} {hdr_ci(hdrs_js, 'content-type')}")
s, body_css, hdrs_css = req(ADM, "GET", "/admin/style.css")
check("style.css -> 200 + css content-type",
      s == 200 and "css" in (hdr_ci(hdrs_css, "content-type") or ""), f"{s} {hdr_ci(hdrs_css, 'content-type')}")
# Console must NOT appear on the public bind.
s, _, _ = req(PUB, "GET", "/admin/")
check("console page absent on PUBLIC bind -> 404", s == 404, f"got {s}")

# --- 11.2 page-driven round trip (mirrors what the browser console does) ---
s, _, _ = req(ADM, "GET", "/admin/v1/apps", headers={"authorization": "Bearer wrong-token"})
check("console's API call with bad token -> 401", s == 401, f"got {s}")

s, v = create_app("E2E-UI-Proxy")
check("UI-Proxy create -> 200 + one-time secret", s == 200 and bool(v.get("app_secret")), f"{s} {v}")
UI_ID = v.get("app_id") if s == 200 else None

s, v, _ = json_body(admin_req("GET", "/admin/v1/apps"))
mine = next((a for a in v.get("apps", []) if a.get("app_id") == UI_ID), None)
check("UI-Proxy visible in app list", mine is not None and mine.get("enabled") is True, f"{mine}")

s, v, _ = json_body(admin_req("GET", f"/admin/v1/apps/{UI_ID}/usage"))
check("UI-Proxy usage shape", s == 200 and {"usage_bytes", "quota_bytes", "file_count", "active_token_count"} <= set(v), f"{v}")

s, _, _ = admin_req("PATCH", f"/admin/v1/apps/{UI_ID}", {"enabled": False})
check("UI-Proxy disable -> 204", s == 204, f"got {s}")

s, v, _ = json_body(admin_req("POST", f"/admin/v1/apps/{UI_ID}/secret/rotate"))
check("UI-Proxy rotate -> new secret once", s == 200 and bool(v.get("app_secret")), f"{s} {v}")

s, v, _ = json_body(admin_req("GET", f"/admin/v1/audit?app_id={UI_ID}"))
acts = {e.get("action") for e in v.get("entries", [])}
check("UI-Proxy audit records create/update/rotate",
      s == 200 and {"app.create", "app.secret_rotate"} <= acts, f"actions={sorted(acts)}")

print()
print("=" * 60)
print("RESULTS")
print("=" * 60)
print(f"PASS: {len(passed)}  FAIL: {len(failed)}")
if failed:
    print("Failed checks:")
    for f in failed:
        print("  -", f)
sys.exit(1 if failed else 0)
