from fastapi import APIRouter, Depends

from app.config import get_app_settings, ecb
from app.dependencies import (
    Token,
    RouteCredentials,
    get_token_for_route,
    validate_scope,
)

from app.crypto import (
    Plaintext,
    Ciphertext,
    Challenge,
    derive_key,
    ecb_encrypt,
    encrypt_challenge,
)

router = APIRouter(prefix="/ecb", tags=["ECB"])

settings = get_app_settings()
route_credentials = RouteCredentials(scope=ecb.scope, password=ecb.password)
validate_access = validate_scope(scope=ecb.scope)

# Key for encrypting the challenge
key = derive_key(ecb.cookie)
challenge = encrypt_challenge(key, ecb.challenge)

# Key for encrypting posted plaintext messages
key = derive_key(settings.key_seed)


@router.post("/token", response_model=Token)
def get_token(token: Token = Depends(get_token_for_route(route_credentials))):
    return token


@router.post("/", dependencies=[Depends(validate_access)], response_model=Ciphertext)
def encrypt_plaintext(plaintext: Plaintext):
    plaintext = plaintext.plaintext + ecb.cookie
    ciphertext = ecb_encrypt(key=key, plaintext=plaintext)
    return ciphertext


@router.get("/challenge", response_model=Challenge)
def read_challenge():
    return challenge
