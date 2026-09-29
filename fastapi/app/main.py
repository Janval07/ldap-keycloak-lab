import os
import httpx
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt, JWTError

KC_INTERNAL=os.getenv("KEYCLOAK_INTERNAL","http://keycloak:8080")
KC_PUBLIC=os.getenv("KEYCLOAK_PUBLIC","http://localhost:8081")
REALM=os.getenv("KEYCLOAK_REALM","cybersecurity")
CLIENT_ID=os.getenv("KEYCLOAK_CLIENT_ID","fastapi-api")
ISSUER=f"{KC_PUBLIC}/realms/{REALM}"
JWKS_URL=f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/certs"

oauth2_scheme=OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{ISSUER}/protocol/openid-connect/auth",
    tokenUrl=f"{ISSUER}/protocol/openid-connect/token",
    scopes={"openid":"OpenID Connect identity"},
)
app=FastAPI(title="LDAP + OAuth 2.0 / OIDC API",version="2.0.0")

@app.get("/health")
def health(): return {"status":"ok"}

async def current_user(token: Annotated[str,Depends(oauth2_scheme)]):
    try:
        async with httpx.AsyncClient() as c:
            r=await c.get(JWKS_URL,timeout=5); r.raise_for_status()
            jwks=r.json()
        header=jwt.get_unverified_header(token)
        key=next((k for k in jwks["keys"] if k.get("kid")==header.get("kid")),None)
        if not key: raise HTTPException(401,"Signing key not found")
        return jwt.decode(token,key,algorithms=["RS256"],audience=CLIENT_ID,issuer=ISSUER)
    except (JWTError,httpx.HTTPError,StopIteration) as e:
        raise HTTPException(401,f"Invalid access token: {e}",headers={"WWW-Authenticate":"Bearer"})

@app.get("/api/profile")
async def profile(user: Annotated[dict,Depends(current_user)]):
    return {"message":"OAuth 2.0 access token accepted","subject":user.get("sub"),
            "username":user.get("preferred_username"),"email":user.get("email"),"issuer":user.get("iss")}
