#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Licensing Service v12 — PostgreSQL (Neon) + Users + Login + Auto-Renew
FastAPI + SQLAlchemy (sync, psycopg2) + Ed25519 + PBKDF2

Endpoints (principais):
- POST /admin/users/create (X-API-Key)
- GET  /admin/users/list   (X-API-Key)
- POST /login              -> auth_code
- POST /claim-auth         -> refresh_token
- POST /renew              (Bearer <refresh_token>) -> licença mensal
- POST /revoke             (X-API-Key)
- GET  /tokens             (X-API-Key)
- GET  /public-key, /healthz
"""
import os, re, json, base64, hashlib, secrets
from datetime import datetime, date, timedelta
from typing import Optional, Literal, Tuple

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, model_validator, Field, ConfigDict

from sqlalchemy import (
    create_engine, select, func,
    String, Integer, Boolean, DateTime, Text, JSON as SA_JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker, Mapped, mapped_column

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


# ===================== Config =====================
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "change-me")  # header X-API-Key

def normalize_db_url(url: str) -> str:
    """Troca 'postgresql://' por 'postgresql+psycopg2://' se precisar."""
    if not url:
        return url
    if url.startswith("postgresql+psycopg2://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL não definido no ambiente")
DATABASE_URL = normalize_db_url(DATABASE_URL)

engine = create_engine(DATABASE_URL, future=True, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


# ===================== Utils =====================
LETTER_VALUES_DEFAULT = {
    "A":3,"B":17,"C":29,"D":11,"E":23,"F":13,"G":31,"H":7,"I":19,"J":5,"K":37,"L":2,"M":41,
    "N":43,"O":47,"P":53,"Q":59,"R":61,"S":67,"T":71,"U":73,"V":79,"W":83,"X":89,"Y":97,"Z":101,
    "0":2,"1":3,"2":5,"3":7,"4":11,"5":13,"6":17,"7":19,"8":23,"9":29
}
def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def today_ym() -> str: return date.today().strftime("%Y-%m")

def eom(ym: str) -> str:
    y, m = map(int, ym.split("-"))
    from calendar import monthrange
    last = monthrange(y, m)[1]
    return datetime(y, m, last, 23, 59, 59).isoformat()

def acc_range(installation_id: str, ym: str, mode: str, fixed_min: int, fixed_max: int, delta: int) -> tuple[int,int]:
    if mode == "fixed":
        return int(fixed_min), int(fixed_max)
    raw = hashlib.sha256(f"{ym}:{installation_id}".encode()).digest()
    base = 500 + (int.from_bytes(raw[:4], "big") % 9500)  # 500..9999
    return max(1, base - delta), base + delta

# PBKDF2
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


# ===================== Tabelas =====================
class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)

class User(Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(80), primary_key=True)
    pwd_salt: Mapped[str] = mapped_column(String(64))
    pwd_hash: Mapped[str] = mapped_column(String(88))
    iter: Mapped[int] = mapped_column(Integer, default=200_000)
    cnpj: Mapped[str] = mapped_column(String(40))
    company_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    range_mode: Mapped[str] = mapped_column(String(10), default="fixed")
    fixed_min: Mapped[int] = mapped_column(Integer, default=310)
    fixed_max: Mapped[int] = mapped_column(Integer, default=315)
    delta: Mapped[int] = mapped_column(Integer, default=3)
    require_sum_code: Mapped[bool] = mapped_column(Boolean, default=False)
    letter_values: Mapped[dict] = mapped_column(SA_JSON, default=LETTER_VALUES_DEFAULT)
    features: Mapped[dict] = mapped_column(SA_JSON, default=dict)
    status: Mapped[str] = mapped_column(String(10), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    activation_code: Mapped[str] = mapped_column(String(50))

class AuthCode(Base):
    __tablename__ = "auth_codes"
    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(10))  # pending/used
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    used_by_installation_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)

class Token(Base):
    __tablename__ = "tokens"
    token: Mapped[str] = mapped_column(String(100), primary_key=True)
    username: Mapped[str] = mapped_column(String(80))
    cnpj: Mapped[str] = mapped_column(String(40))
    company_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    installation_id: Mapped[str] = mapped_column(String(120))
    range_mode: Mapped[str] = mapped_column(String(10))
    fixed_min: Mapped[int] = mapped_column(Integer)
    fixed_max: Mapped[int] = mapped_column(Integer)
    delta: Mapped[int] = mapped_column(Integer)
    letter_values: Mapped[dict] = mapped_column(SA_JSON)
    require_sum_code: Mapped[bool] = mapped_column(Boolean)
    features: Mapped[dict] = mapped_column(SA_JSON)
    status: Mapped[str] = mapped_column(String(10), default="active")  # active/revoked
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

class LicenseLog(Base):
    __tablename__ = "licenses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ym: Mapped[str] = mapped_column(String(7))
    cnpj: Mapped[str] = mapped_column(String(40))
    installation_id: Mapped[str] = mapped_column(String(120))
    payload: Mapped[dict] = mapped_column(SA_JSON)
    signature: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)


# ===================== Chaves Ed25519 =====================
def get_or_create_keys():
    with SessionLocal() as s:
        priv_row = s.get(Setting, "ed25519_private_pem")
        pub_row  = s.get(Setting, "ed25519_public_pem")
        if priv_row and pub_row:
            priv = serialization.load_pem_private_key(priv_row.value.encode(), password=None)
            pub  = serialization.load_pem_public_key(pub_row.value.encode())
            return priv, pub
        priv = Ed25519PrivateKey.generate()
        pub  = priv.public_key()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        s.merge(Setting(key="ed25519_private_pem", value=priv_pem))
        s.merge(Setting(key="ed25519_public_pem",  value=pub_pem))
        s.commit()
        return priv, pub

priv, pub = get_or_create_keys()

def public_key_pem() -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
def key_id() -> str:
    return hashlib.sha256(public_key_pem()).hexdigest()[:16]
def sign(payload: dict) -> str:
    msg = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return b64u(priv.sign(msg))


# ===================== Schemas =====================
class LicPayload(BaseModel):
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
    def _default_ym(cls, v): return v or today_ym()

    @model_validator(mode="after")
    def _check_fixed(self):
        if self.range_mode == "fixed":
            if self.fixed_min is None or self.fixed_max is None:
                raise ValueError("fixed_min/fixed_max obrigatórios")
            if self.fixed_min > self.fixed_max:
                raise ValueError("fixed_min <= fixed_max")
        return self


# ===================== FastAPI =====================
app = FastAPI(title="Licensing Service v12 (DB)", version="1.0.0")

@app.get("/")
def root():
    return {"ok": True, "service": "Licensing Service v12 (DB)", "version": "1.0.0", "docs": "/docs"}

@app.get("/public-key")
def get_pk():
    return {"key_id": key_id(), "public_key_pem": public_key_pem().decode()}

@app.get("/healthz")
def healthz():
    try:
        with SessionLocal() as s:
            s.execute(select(func.now()))
        return {"ok": True, "key_id": key_id()}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)

def _mask_url(url: str) -> str:
    # mascara senha em ...://user:password@host/...
    return re.sub(r"(://[^:]+:)([^@]+)(@)", r"\1***\3", url)

@app.get("/admin/debug/paths")
def debug_paths(x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    return {"DATABASE_URL": _mask_url(DATABASE_URL), "driver": "psycopg2", "key_id": key_id()}

# ---- Admin: Users ----
@app.post("/admin/users/create")
def admin_create_user(req: UserCreate, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    hp = hash_password(req.password)
    with SessionLocal() as s:
        if s.get(User, req.username):
            raise HTTPException(409, "username already exists")
        u = User(
            username=req.username,
            pwd_salt=hp["salt"], pwd_hash=hp["hash"], iter=hp["iter"],
            cnpj=req.cnpj, company_name=req.company_name or None,
            range_mode=req.range_mode, fixed_min=req.fixed_min, fixed_max=req.fixed_max, delta=req.delta,
            require_sum_code=req.require_sum_code, letter_values=LETTER_VALUES_DEFAULT,
            features=req.features or {}, status=req.status, created_at=datetime.utcnow(),
            activation_code=secrets.token_urlsafe(16)
        )
        s.add(u); s.commit()
        return {"ok": True, "username": u.username, "activation_code": u.activation_code}

@app.get("/admin/users/list")
def admin_list_users(x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    with SessionLocal() as s:
        rows = s.execute(select(User)).scalars().all()
        out = {}
        for u in rows:
            out[u.username] = {
                "cnpj": u.cnpj, "company_name": u.company_name, "range_mode": u.range_mode,
                "fixed_min": u.fixed_min, "fixed_max": u.fixed_max, "delta": u.delta,
                "require_sum_code": u.require_sum_code, "letter_values": u.letter_values,
                "features": u.features, "status": u.status,
                "created_at": u.created_at.isoformat() + "Z", "activation_code": u.activation_code
            }
        return {"count": len(out), "users": out}

@app.post("/admin/users/disable")
def admin_disable_user(req: UserDisable, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    with SessionLocal() as s:
        u = s.get(User, req.username)
        if not u: raise HTTPException(404, "user not found")
        u.status = "disabled" if req.disabled else "active"
        s.commit()
        return {"ok": True, "username": u.username, "status": u.status}

@app.post("/admin/users/reset-pass")
def admin_reset_pass(req: UserResetPass, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    hp = hash_password(req.new_password)
    with SessionLocal() as s:
        u = s.get(User, req.username)
        if not u: raise HTTPException(404, "user not found")
        u.pwd_salt, u.pwd_hash, u.iter = hp["salt"], hp["hash"], hp["iter"]
        s.commit()
        return {"ok": True}

# ---- Client: Login / Claim / Renew ----
@app.post("/login")
def login(req: LoginReq):
    with SessionLocal() as s:
        u = s.get(User, req.username)
        if not u or u.status != "active":
            raise HTTPException(401, "invalid credentials")
        rec = {"salt": u.pwd_salt, "hash": u.pwd_hash, "iter": u.iter}
        if not verify_password(req.password, rec):
            raise HTTPException(401, "invalid credentials")
        code = secrets.token_urlsafe(24)
        ac = AuthCode(code=code, username=u.username,
                      created_at=datetime.utcnow(),
                      expires_at=datetime.utcnow()+timedelta(minutes=10),
                      status="pending")
        s.add(ac); s.commit()
        return {"auth_code": code, "expires_in_min": 10}

@app.post("/claim-auth")
def claim_auth(req: ClaimAuthReq):
    with SessionLocal() as s:
        ac = s.get(AuthCode, req.auth_code)
        if not ac: raise HTTPException(400, "invalid auth_code")
        if ac.status != "pending": raise HTTPException(400, "auth_code already used")
        if ac.expires_at < datetime.utcnow(): raise HTTPException(400, "auth_code expired")
        u = s.get(User, ac.username)
        if not u or u.status != "active": raise HTTPException(403, "user disabled")
        token = secrets.token_urlsafe(32)
        t = Token(
            token=token, username=u.username, cnpj=u.cnpj, company_name=u.company_name,
            installation_id=req.installation_id, range_mode=u.range_mode,
            fixed_min=u.fixed_min, fixed_max=u.fixed_max, delta=u.delta,
            letter_values=u.letter_values, require_sum_code=u.require_sum_code,
            features=u.features, status="active", created_at=datetime.utcnow()
        )
        ac.status = "used"; ac.used_at = datetime.utcnow(); ac.used_by_installation_id = req.installation_id
        s.add(t); s.commit()
        return {"refresh_token": token, "status": "active"}

@app.post("/renew")
async def renew(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): raise HTTPException(401, "missing bearer token")
    token = auth.split(" ", 1)[1]

    with SessionLocal() as s:
        t = s.get(Token, token)
        if not t: raise HTTPException(401, "invalid token")
        if t.status != "active": raise HTTPException(403, "token revoked")

        ym = today_ym()
        rmin, rmax = acc_range(t.installation_id, ym, t.range_mode, t.fixed_min, t.fixed_max, t.delta)
        payload = LicPayload(
            ym=ym, cnpj=t.cnpj, company_name=t.company_name,
            installation_id=t.installation_id, range_mode=t.range_mode,
            accepted_range=(rmin, rmax), require_sum_code=t.require_sum_code,
            letter_values=t.letter_values, features=t.features,
            issued_at=datetime.utcnow().isoformat() + "Z",
            expires_at=eom(ym),
            key_id=key_id(),
        ).model_dump(by_alias=True)

        token_json = {"license": payload, "signature": sign(payload), "key_id": key_id()}

        # log opcional
        s.add(LicenseLog(
            ym=ym, cnpj=t.cnpj, installation_id=t.installation_id,
            payload=token_json["license"], signature=token_json["signature"]
        ))
        s.commit()
        return JSONResponse(token_json)

@app.post("/revoke")
def revoke(req: RevokeReq, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    with SessionLocal() as s:
        t = s.get(Token, req.token)
        if not t: raise HTTPException(404, "token not found")
        t.status = "revoked"; t.revoked_at = datetime.utcnow()
        s.commit(); return {"ok": True}

@app.get("/tokens")
def list_tokens(x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    with SessionLocal() as s:
        rows = s.execute(select(Token)).scalars().all()
        out = { t.token: {
            "username": t.username, "cnpj": t.cnpj, "company_name": t.company_name,
            "installation_id": t.installation_id, "range_mode": t.range_mode,
            "fixed_min": t.fixed_min, "fixed_max": t.fixed_max, "delta": t.delta,
            "letter_values": t.letter_values, "require_sum_code": t.require_sum_code,
            "features": t.features, "status": t.status,
            "created_at": t.created_at.isoformat() + "Z",
            "revoked_at": t.revoked_at.isoformat() + "Z" if t.revoked_at else None
        } for t in rows }
        return {"count": len(out), "tokens": out}

@app.post("/issue")
def issue(req: IssueReq, x_api_key: str = Header(default="")):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, "unauthorized")
    rmin, rmax = acc_range(
        req.installation_id, req.ym, req.range_mode,
        req.fixed_min or 0, req.fixed_max or 0, req.delta or 0
    )
    lv = req.letter_values or LETTER_VALUES_DEFAULT
    payload = LicPayload(
        ym=req.ym or today_ym(), cnpj=req.cnpj, company_name=req.company_name,
        installation_id=req.installation_id, range_mode=req.range_mode,
        accepted_range=(rmin, rmax), require_sum_code=req.require_sum_code,
        letter_values=lv, features=req.features,
        issued_at=datetime.utcnow().isoformat() + "Z",
        expires_at=req.expires_at or eom(req.ym or today_ym()), key_id=key_id(),
    ).model_dump(by_alias=True)
    token_json = {"license": payload, "signature": sign(payload), "key_id": key_id()}
    with SessionLocal() as s:
        s.add(LicenseLog(
            ym=payload["ym"], cnpj=req.cnpj, installation_id=req.installation_id,
            payload=token_json["license"], signature=token_json["signature"]
        ))
        s.commit()
    return token_json


# Dev local
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("licensing_service_auto:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
