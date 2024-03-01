from fastapi import APIRouter, Depends, HTTPException
from base64 import b64decode

from app.config import get_app_settings, cbc
from app.dependencies import (
    Token,
    RouteCredentials,
    get_token_for_route,
    validate_scope,
)

from app.crypto import (
    Plaintext,
    Challenge,
    derive_key,
    cbc_encrypt_hex,
    encrypt_challenge,
)


router = APIRouter(prefix=cbc.prefix, tags=["CBC"])

route_credentials = RouteCredentials(scope=cbc.scope, password=cbc.password)
validate_access = validate_scope(scope=cbc.scope)
settings = get_app_settings()

key = derive_key(settings.key_seed)
encrypted_cookie = cbc_encrypt_hex(key, cbc.cookie.encode().hex())
iv = b64decode(encrypted_cookie.iv)
iv = int.from_bytes(iv, byteorder="big")

# Key for encrypting the challenge
challenge_key = derive_key(cbc.cookie)
challenge = encrypt_challenge(challenge_key, cbc.challenge)


@router.post("/token", response_model=Token)
def get_token(token: Token = Depends(get_token_for_route(route_credentials))):
    return token


@router.post("/iv", dependencies=[Depends(validate_access)], response_model=Challenge)
def encrypt_plaintext(plaintext: Plaintext):
    global iv  # to avoid iv becoming local to this scope
    iv += cbc.iv_increment
    try:
        ciphertext = cbc_encrypt_hex(
            key=key, plaintext=plaintext.plaintext, iv=iv.to_bytes(16, byteorder="big")
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=repr(error))
    return ciphertext


@router.get("/iv/encrypted_cookie", response_model=Challenge)
def read_encrypted_cookie():
    return encrypted_cookie


@router.get("/iv/challenge", response_model=Challenge)
def read_challenge():
    return challenge
