#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Licensing Service — Auto-Renew (FastAPI + Ed25519) [Pydantic v2]
Endpoints:
- GET  /public-key
- GET  /healthz
- POST /register  (admin, X-API-Key)
- POST /renew     (client, Bearer)
- POST /revoke    (admin, X-API-Key)
- GET  /tokens    (admin, X-API-Key)
- POST /issue     (admin, X-API-Key)
"""
import os, json, base64, hashlib, secrets
from datetime import datetime, date
from pathlib import Path
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, model_validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

APP_DIR = Path(os.getenv('APP_DIR','.'))
KEYS_DIR = APP_DIR / 'keys'; DATA_DIR = APP_DIR / 'data'
KEYS_DIR.mkdir(parents=True, exist_ok=True); DATA_DIR.mkdir(parents=True, exist_ok=True)
PRIV = KEYS_DIR / 'ed25519_private.pem'; PUB = KEYS_DIR / 'ed25519_public.pem'
TOKENS_DB = DATA_DIR / 'tokens.json'
ADMIN_API_KEY = os.getenv('ADMIN_API_KEY','change-me')

LETTER_VALUES_DEFAULT = {'A':3,'B':17,'C':29,'D':11,'E':23,'F':13,'G':31,'H':7,'I':19,'J':5,'K':37,'L':2,'M':41,'N':43,'O':47,'P':53,'Q':59,'R':61,'S':67,'T':71,'U':73,'V':79,'W':83,'X':89,'Y':97,'Z':101,'0':2,'1':3,'2':5,'3':7,'4':11,'5':13,'6':17,'7':19,'8':23,'9':29}
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')

def load_or_create_keys():
    if PRIV.exists() and PUB.exists():
        priv = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
        pub = serialization.load_pem_public_key(PUB.read_bytes())
        return priv, pub
    priv = Ed25519PrivateKey.generate(); pub = priv.public_key()
    PRIV.write_bytes(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    PUB.write_bytes(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub
priv, pub = load_or_create_keys()

def public_key_pem(): return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
def key_id(): return hashlib.sha256(public_key_pem()).hexdigest()[:16]
def sign(payload: dict) -> str:
    msg = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',',':')).encode()
    return b64u(priv.sign(msg))
def today_ym() -> str: return date.today().strftime('%Y-%m')
def eom(ym: str) -> str:
    y,m = map(int, ym.split('-'))
    from calendar import monthrange
    last = monthrange(y, m)[1]
    return datetime(y, m, last, 23, 59, 59).isoformat()
def acc_range(inst: str, ym: str, mode: str, fmin: int, fmax: int, delta: int):
    if mode=='fixed': return int(fmin), int(fmax)
    raw = hashlib.sha256(f'{ym}:{inst}'.encode()).digest()
    base = 500 + (int.from_bytes(raw[:4],'big') % 9500)
    return max(1, base-delta), base+delta

def load_tokens():
    if TOKENS_DB.exists():
        try: return json.loads(TOKENS_DB.read_text(encoding='utf-8'))
        except Exception: pass
    return {"tokens": {}}

def save_tokens(db):
    TOKENS_DB.parent.mkdir(parents=True, exist_ok=True)
    TOKENS_DB.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding='utf-8')

class IssueReq(BaseModel):
    cnpj: str
    company_name: Optional[str]=None
    installation_id: str
    ym: Optional[str]=None
    range_mode: Literal['fixed','delta']='fixed'
    fixed_min: Optional[int]=310
    fixed_max: Optional[int]=315
    delta: Optional[int]=3
    letter_values: Optional[dict]=None
    require_sum_code: bool=True
    features: Optional[dict]=None
    expires_at: Optional[str]=None

    @field_validator('ym', mode='before')
    @classmethod
    def _default_ym(cls, v):
        return v or today_ym()

    @model_validator(mode='after')
    def _check_fixed(self):
        if self.range_mode == 'fixed':
            if self.fixed_min is None or self.fixed_max is None:
                raise ValueError('fixed_min/fixed_max obrigatórios no modo fixed')
            if self.fixed_min > self.fixed_max:
                raise ValueError('fixed_min deve ser <= fixed_max')
        return self

class LicPayload(BaseModel):
    schema: str='v1'
    ym: str
    cnpj: str
    company_name: Optional[str]
    installation_id: str
    range_mode: str
    accepted_range: tuple[int,int]
    require_sum_code: bool=True
    letter_values: dict
    features: Optional[dict]=None
    issued_at: str
    expires_at: str
    key_id: str

class RegisterReq(BaseModel):
    cnpj: str
    company_name: Optional[str]=None
    installation_id: str
    range_mode: Literal['fixed','delta']='fixed'
    fixed_min: int=310
    fixed_max: int=315
    delta: int=3
    letter_values: Optional[dict]=None
    require_sum_code: bool=False
    features: Optional[dict]=None

class RevokeReq(BaseModel):
    token: str

from fastapi import FastAPI
app = FastAPI(title='Licensing Service (Auto-Renew)', version='1.0.7')

@app.get('/public-key')
def get_pk(): return {'key_id': key_id(), 'public_key_pem': public_key_pem().decode()}

@app.get('/healthz')
def healthz(): return {'ok': True, 'key_id': key_id()}

@app.post('/issue')
def issue(req: IssueReq, x_api_key: str = Header(default='')):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, 'unauthorized')
    rmin, rmax = acc_range(req.installation_id, req.ym, req.range_mode, req.fixed_min or 0, req.fixed_max or 0, req.delta or 0)
    lv = req.letter_values or LETTER_VALUES_DEFAULT
    payload = LicPayload(ym=req.ym, cnpj=req.cnpj, company_name=req.company_name, installation_id=req.installation_id,
                         range_mode=req.range_mode, accepted_range=(rmin,rmax), require_sum_code=req.require_sum_code,
                         letter_values=lv, features=req.features, issued_at=datetime.utcnow().isoformat()+'Z',
                         expires_at=req.expires_at or eom(req.ym), key_id=key_id()).dict()
    token = {'license': payload, 'signature': sign(payload), 'key_id': key_id()}
    out = (DATA_DIR/'licenses'/req.ym); out.mkdir(parents=True, exist_ok=True)
    (out/f'{req.cnpj}_{req.installation_id}_{req.ym}.json').write_text(json.dumps(token, ensure_ascii=False, indent=2), encoding='utf-8')
    return token

@app.post('/register')
def register(req: RegisterReq, x_api_key: str = Header(default='')):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, 'unauthorized')
    db = load_tokens()
    token = secrets.token_urlsafe(32)  # refresh token
    db['tokens'][token] = {
        "cnpj": req.cnpj, "company_name": req.company_name, "installation_id": req.installation_id,
        "range_mode": req.range_mode, "fixed_min": int(req.fixed_min), "fixed_max": int(req.fixed_max), "delta": int(req.delta),
        "letter_values": req.letter_values or LETTER_VALUES_DEFAULT, "require_sum_code": bool(req.require_sum_code),
        "features": req.features or {}, "status": "active", "created_at": datetime.utcnow().isoformat()+'Z'
    }
    save_tokens(db)
    return {"refresh_token": token, "status": "active"}

@app.post('/revoke')
def revoke(req: RevokeReq, x_api_key: str = Header(default='')):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, 'unauthorized')
    db = load_tokens()
    if req.token in db['tokens']:
        db['tokens'][req.token]['status'] = 'revoked'
        save_tokens(db)
        return {"ok": True}
    raise HTTPException(404, "token not found")

@app.get('/tokens')
def list_tokens(x_api_key: str = Header(default='')):
    if x_api_key != ADMIN_API_KEY: raise HTTPException(401, 'unauthorized')
    db = load_tokens()
    return {"count": len(db['tokens']), "tokens": db['tokens']}

@app.post('/renew')
async def renew(request: Request):
    auth = request.headers.get('Authorization','')
    if not auth.startswith('Bearer '): raise HTTPException(401, 'missing bearer token')
    token = auth.split(' ',1)[1]
    db = load_tokens()
    rec = db['tokens'].get(token)
    if not rec: raise HTTPException(401, 'invalid token')
    if rec.get('status') != 'active': raise HTTPException(403, 'token revoked')

    ym = today_ym()
    rmin, rmax = acc_range(rec['installation_id'], ym, rec['range_mode'], rec['fixed_min'], rec['fixed_max'], rec['delta'])
    payload = LicPayload(
        ym=ym, cnpj=rec['cnpj'], company_name=rec['company_name'], installation_id=rec['installation_id'],
        range_mode=rec['range_mode'], accepted_range=(rmin,rmax), require_sum_code=rec['require_sum_code'],
        letter_values=rec['letter_values'], features=rec['features'],
        issued_at=datetime.utcnow().isoformat()+'Z', expires_at=eom(ym), key_id=key_id()
    ).dict()
    token_json = {'license': payload, 'signature': sign(payload), 'key_id': key_id()}
    out = (DATA_DIR/'licenses'/ym); out.mkdir(parents=True, exist_ok=True)
    fname = f"{rec['cnpj']}_{rec['installation_id']}_{ym}.json"
    (out/fname).write_text(json.dumps(token_json, ensure_ascii=False, indent=2), encoding='utf-8')
    return JSONResponse(token_json)

if __name__=='__main__':
    import uvicorn, os
    uvicorn.run('licensing_service_auto:app', host='0.0.0.0', port=int(os.getenv('PORT','8000')), reload=False)
