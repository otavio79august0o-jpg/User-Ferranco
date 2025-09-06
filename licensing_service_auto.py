#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Licensing Service v11 — Users + Login (one-time code) + Auto-Renew
FastAPI + Ed25519 + PBKDF2

Endpoints:
- GET  /                -> ping
- GET  /public-key
- GET  /healthz
- POST /admin/users/create     (admin) -> cria usuário
- GET  /admin/users/list       (admin)
- POST /admin/users/disable    (admin)
- POST /admin/users/reset-pass (admin)
- POST /login                  (client) -> username+password -> auth_code (uso único)
- POST /claim-auth             (client) -> auth_code+installation_id -> refresh_token
- POST /renew                  (client) -> baixa licença do mês usando refresh_token
- POST /revoke                 (admin)  -> revoga refresh_token
- GET  /tokens                 (admin)  -> auditoria
- POST /issue                  (admin)  -> emite JSON de licença manual (debug)
"""
import os, json, base64, hashlib, secrets, re
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional, Literal, Tuple

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, model_validator, Field, ConfigDict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# --------- Paths e configuração ---------
APP_DIR = Path(os.getenv("APP_DIR", "."))  # no Render, defina: APP_DIR=/var/data/licensing
KEYS_DIR = APP_DIR / "keys"
DATA_DIR = APP_DIR / "data"
KEYS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

PRIV = KEYS_DIR / "ed25519_private.pem"
PUB  = KEYS_DIR / "ed25519_public.pem"
DB_PATH = DATA_DIR / "db.json"

# Defina no Render (Settings -> Environment):
# ADMIN_API_KEY = TavimdoCorre3003
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "change-me")

# --------- Utilidades ---------
LETTER_VALUES_DEFAULT = {
    "A":3,"B":17,"C":29,"D":11,"E":23,"F":13,"G":31,"H":7,"I":19,"J":5,"K":37,"L":2,"M":41,
    "N":43,"O":47,"P":53,"Q":59,"R":61,"S":67,"T":71,"U":73,"V":79,"W":83,"X":89,"Y":97,"Z":101,
    "0":2,"1":3,"2":5,"3":7,"4":11,"5":13,"6":17,"7":19,"8":23,"9":29
}
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")

def _safe_name(s: str) -> str:
    """Converte string para nome de arquivo seguro (remove/ troca caracteres inválidos)."""
    s = (s or "").strip()
    return re.sub(r'[^A-Za-z0-9_.-]+', '-', s)

def load_or_create_keys():
    if PRIV.exists() and PUB.exists():
        priv = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
        pub  = serialization.load_pem_public_key(PUB.read_bytes())
        return priv, pub
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    PRIV.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    PUB.write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv, pub

priv, pub = load_or_create_keys()

def public_key_pem() -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def key_id() -> str:
    return hashlib.sha256(public_key_pem()).hexdigest()[:16]

def sign(payload: dict) -> str:
    msg = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return b64u(priv.sign(msg))

def today_ym() -> str:
    return date.today().strftime("%Y-%m")

def eom(ym: str) -> str:
    y, m = map(int, ym.split("-"))
    from calendar import monthrange
    last = monthrange(y, m)[1]
    return datetime(y, m, last, 23, 59, 59).isoformat()

def acc_range(installation_id: str, ym: str, mode: str, fixed_min: int, fixed_max: int, delta: int):
    if mode == "fixed":
        return int(fixed_min), int(fixed_max)
    # modo "delta": base varia por (ym + installation_id)
    raw = hashlib.sha256(f"{ym}:{installation_id}".encode()).digest()
    base = 500 + (int.from_bytes(raw[:4], "big") % 9500)  # 500..9999
    return max(1, base - delta), base + delta

# --------- DB (arquivo JSON) ---------
def load_db() -> dict:
    if DB_PATH.exists():
        try:
            db = json.loads(DB_PATH.read_text(encoding="utf-8"))
            db.setdefault("tokens", {})
            db.setdefault("users", {})
            db.setdefault("auth_codes", {})
            return db
        except Exception:
            pass
    return {"tokens": {}, "users": {}, "auth_codes": {}}

def save_db(db: dict) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    DB_PATH.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")

# --------- Senhas (PBKDF2) ---------
def hash_password(pwd: str) -> dict:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 200_000)
    return {"salt": b64u(salt), "hash": b64u(dk), "algo": "pbkdf2_sha256", "iter": 200_000}

def verify_password(pwd: str, rec: dict) -> bool:
    try:
        salt = base64.urlsafe_b64decode(rec["salt"] + "=" * (-len(rec["salt"]) % 4))
        expected = base64.urlsafe_b64decode(rec["hash"] + "=" * (-len(rec["hash"]) % 4))
        dk = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, int(rec.get("iter", 200_000)))
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False

# --------- Schemas ---------
class LicPayload(BaseModel):
    # Evita warning do Pydantic usando alias "schema"
    model_config = ConfigDict(populate_by_name=True)

    schema_version: str = Field('v1', alias='schema')
    ym: str
    cnpj: str
    company_name: Optional[str]
    installation_id: str
    range_mode: str
    accepted_range: Tuple[int, int]
    require_sum_code: bool = True
    letter_values: dict
    features: Optional[dict] = None
    issued_at: str
    expires_at: str
    key_id: str

class UserCreate(BaseModel):
    username: str
    password: str
    cnpj: str
    company_name: Optional[str] = None
    range_mode: Literal["fixed", "delta"] = "fixed"
    fixed_min: int = 310
    fixed_max: int = 315
    delta: int = 3
    require_sum_code: bool = False
    features: Optional[dict] = None
    status: Literal["active", "disabled"] = "active"

class UserResetPass(BaseModel):
    username: str
    new_password: str

class UserDisable(BaseModel):
    username: str
    disabled: bool = True

class LoginReq(BaseModel):
    username: str
    password: str

class ClaimAuthReq(BaseModel):
    auth_code: str
    installation_id: str

class RevokeReq(BaseModel):
    token: str

class IssueReq(BaseModel):
    cnpj: str
    company_name: Optional[str] = None
    installation_id: str
    ym: Optional[str] = None
    range_mode: Literal["fixed", "delta"] = "fixed"
    fixed_min: Optional[int] = 310
    fixed_max: Optional[int] = 315
    delta: Optional[int] = 3
    letter_values: Optional[dict] = None
    require_sum_code: bool = True
    features: Optional[dict] = None
    expires_at: Optional[str] = None

    @field_validator("ym", mode="before")
    @classmethod
    def _default_ym(cls, v):
        return v or today_ym()

    @model_validator(mode="after")
    def _check_fixed(self):
        if self.range_mode == "fixed":
            if self.fixed_min is None or self.fixed_max is None:
                raise ValueError("fixed_min/fixed_max obrigatórios")
            if self.fixed_min > self.fixed_max:
                raise ValueError("fixed_min <= fixed_max")
        return self

# --------- FastAPI ---------
app = FastAPI(title="Licensing Service v11 (Users + Login + Auto-Renew)", version="1.0.0")

@app.get("/")
def root():
    return {"ok": True, "service": "Licensing Service v11", "version": "1.0.0", "docs": "/docs"}

@app.get("/public-key")
def get_pk():
    return {"key_id": key_id(), "public_key_pem": public_key_pem().decode()}

@app.get("/healthz")
def healthz():
    return {"ok": True, "key_id": key_id()}

# ----- Admin: Users -----
@app.post("/admin/users/create")
def admin_create_user(req: UserCreate, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "unauthorized")
    db = load_db()
    if req.username in db["users"]:
        raise HTTPException(409, "username already exists")
    pwd = hash_password(req.password)
    activation_code = secrets.token_urlsafe(16)  # informativo
    db["users"][req.username] = {
        "pwd": pwd,
        "cnpj": req.cnpj,
        "company_name": req.company_name,
        "range_mode": req.range_mode,
        "fixed_min": int(req.fixed_min),
        "fixed_max": int(req.fixed_max),
        "delta": int(req.delta),
        "require_sum_code": bool(req.require_sum_code),
        "letter_values": LETTER_VALUES_DEFAULT,
        "features": req.features or {},
        "status": req.status,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "activation_code": activation_code,
    }
    save_db(db)
    return {"ok": True, "username": req.username, "activation_code": activation_code}

@app.get("/admin/users/list")
def admin_list_users(x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "unauthorized")
    db = load_db()
    out = {u: {k: v for k, v in rec.items() if k != "pwd"} for u, rec in db["users"].items()}
    return {"count": len(out), "users": out}

@app.post("/admin/users/disable")
def admin_disable_user(req: UserDisable, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "unauthorized")
    db = load_db()
    rec = db["users"].get(req.username)
    if not rec:
        raise HTTPException(404, "user not found")
    rec["status"] = "disabled" if req.disabled else "active"
    save_db(db)
    return {"ok": True, "username": req.username, "status": rec["status"]}

@app.post("/admin/users/reset-pass")
def admin_reset_pass(req: UserResetPass, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "unauthorized")
    db = load_db()
    rec = db["users"].get(req.username)
    if not rec:
        raise HTTPException(404, "user not found")
    rec["pwd"] = hash_password(req.new_password)
    save_db(db)
    return {"ok": True}

# ----- Client: Login -> one-time auth_code -----
@app.post("/login")
def login(req: LoginReq):
    db = load_db()
    u = db["users"].get(req.username)
    if not u or u.get("status") != "active" or not verify_password(req.password, u.get("pwd", {})):
        raise HTTPException(401, "invalid credentials")
    code = secrets.token_urlsafe(24)
    db["auth_codes"][code] = {
        "username": req.username,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z",
        "status": "pending",
    }
    save_db(db)
    return {"auth_code": code, "expires_in_min": 10}

# ----- Client: claim-auth -> refresh_token (bind installation_id) -----
@app.post("/claim-auth")
def claim_auth(req: ClaimAuthReq):
    db = load_db()
    ac = db["auth_codes"].get(req.auth_code)
    if not ac:
        raise HTTPException(400, "invalid auth_code")
    if ac.get("status") != "pending":
        raise HTTPException(400, "auth_code already used")
    try:
        if datetime.fromisoformat(ac["expires_at"].replace("Z", "")) < datetime.utcnow():
            raise HTTPException(400, "auth_code expired")
    except Exception:
        pass
    user = db["users"].get(ac["username"])
    if not user or user.get("status") != "active":
        raise HTTPException(403, "user disabled")

    token = secrets.token_urlsafe(32)
    db["tokens"][token] = {
        "username": ac["username"],
        "cnpj": user["cnpj"],
        "company_name": user.get("company_name"),
        "installation_id": req.installation_id,
        "range_mode": user["range_mode"],
        "fixed_min": int(user["fixed_min"]),
        "fixed_max": int(user["fixed_max"]),
        "delta": int(user["delta"]),
        "letter_values": user["letter_values"],
        "require_sum_code": bool(user["require_sum_code"]),
        "features": user.get("features", {}),
        "status": "active",
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    ac["status"] = "used"
    ac["used_at"] = datetime.utcnow().isoformat() + "Z"
    ac["used_by_installation_id"] = req.installation_id
    save_db(db)
    return {"refresh_token": token, "status": "active"}

# ----- Client: renew (licença mensal) -----
@app.post("/renew")
async def renew(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    token = auth.split(" ", 1)[1]

    db = load_db()
    rec = db["tokens"].get(token)
    if not rec:
        raise HTTPException(401, "invalid token")
    if rec.get("status") != "active":
        raise HTTPException(403, "token revoked")

    ym = today_ym()
    rmin, rmax = acc_range(
        rec["installation_id"], ym, rec["range_mode"],
        rec["fixed_min"], rec["fixed_max"], rec.get("delta", 3)
    )
    payload = LicPayload(
        ym=ym,
        cnpj=rec["cnpj"],
        company_name=rec.get("company_name"),
        installation_id=rec["installation_id"],
        range_mode=rec["range_mode"],
        accepted_range=(rmin, rmax),
        require_sum_code=rec.get("require_sum_code", False),
        letter_values=rec["letter_values"],
        features=rec.get("features", {}),
        issued_at=datetime.utcnow().isoformat() + "Z",
        expires_at=eom(ym),
        key_id=key_id(),
    ).model_dump(by_alias=True)

    token_json = {"license": payload, "signature": sign(payload), "key_id": key_id()}
    out_dir = DATA_DIR / "licenses" / ym
    out_dir.mkdir(parents=True, exist_ok=True)

    cnpj_safe = _safe_name(rec["cnpj"])
    inst_safe = _safe_name(rec["installation_id"])
    fname = f"{cnpj_safe}_{inst_safe}_{ym}.json"

    (out_dir / fname).write_text(json.dumps(token_json, ensure_ascii=False, indent=2), encoding="utf-8")
    return JSONResponse(token_json)

# ----- Admin: revoke token & list tokens -----
@app.post("/revoke")
def revoke(req: RevokeReq, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "unauthorized")
    db = load_db()
    if req.token in db["tokens"]:
        db["tokens"][req.token]["status"] = "revoked"
        db["tokens"][req.token]["revoked_at"] = datetime.utcnow().isoformat() + "Z"
        save_db(db)
        return {"ok": True}
    raise HTTPException(404, "token not found")

@app.get("/tokens")
def list_tokens(x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "unauthorized")
    db = load_db()
    return {"count": len(db["tokens"]), "tokens": db["tokens"]}

# ----- Opcional: emissão manual (debug) -----
@app.post("/issue")
def issue(req: IssueReq, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(401, "unauthorized")
    rmin, rmax = acc_range(
        req.installation_id, req.ym, req.range_mode,
        req.fixed_min or 0, req.fixed_max or 0, req.delta or 0
    )
    lv = req.letter_values or LETTER_VALUES_DEFAULT
    payload = LicPayload(
        ym=req.ym,
        cnpj=req.cnpj,
        company_name=req.company_name,
        installation_id=req.installation_id,
        range_mode=req.range_mode,
        accepted_range=(rmin, rmax),
        require_sum_code=req.require_sum_code,
        letter_values=lv,
        features=req.features,
        issued_at=datetime.utcnow().isoformat() + "Z",
        expires_at=req.expires_at or eom(req.ym),
        key_id=key_id(),
    ).model_dump(by_alias=True)

    token = {"license": payload, "signature": sign(payload), "key_id": key_id()}
    out = DATA_DIR / "licenses" / req.ym
    out.mkdir(parents=True, exist_ok=True)

    cnpj_safe = _safe_name(req.cnpj)
    inst_safe = _safe_name(req.installation_id)
    (out / f"{cnpj_safe}_{inst_safe}_{req.ym}.json").write_text(
        json.dumps(token, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return token

# ----- Main (dev local) -----
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("licensing_service_auto:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
