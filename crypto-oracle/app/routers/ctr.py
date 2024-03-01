from fastapi import APIRouter, Depends
from base64 import b64decode

from Crypto.Random import random

from app.config import get_app_settings, ctr
from app.dependencies import (
    Token,
    RouteCredentials,
    get_token_for_route,
    validate_scope,
)

from app.crypto import CtrPlaintext, CtrModeCiphertext, derive_key, ctr_encrypt


router = APIRouter(prefix=ctr.prefix, tags=["CTR"])

route_credentials = RouteCredentials(scope=ctr.scope, password=ctr.password)
validate_access = validate_scope(scope=ctr.scope)
settings = get_app_settings()

key = derive_key(settings.key_seed)
challenge = ctr_encrypt(key, ctr.challenge)
nonce = bytearray(b64decode(challenge.nonce))

# Prepare a fixed part of nonce values to follow
bytes_count = ctr.difficulty // 8
reminder = ctr.difficulty % 8
mask = (1 << (8 - reminder)) - 1
nonce[bytes_count] &= mask


@router.post("/token", response_model=Token)
def get_token(token: Token = Depends(get_token_for_route(route_credentials))):
    return token


@router.post(
    "/", dependencies=[Depends(validate_access)], response_model=CtrModeCiphertext
)
def encrypt_plaintext(plaintext: CtrPlaintext):
    # Prepare a random part of the next nonce
    for i in range(bytes_count):
        nonce[i] = random.randint(0, 255)
    nonce[bytes_count] ^= random.getrandbits(reminder) << (8 - reminder)

    ciphertext = ctr_encrypt(key=key, plaintext=plaintext.plaintext, nonce=bytes(nonce))

    return ciphertext


@router.get("/challenge", response_model=CtrModeCiphertext)
def read_challenge():
    return challenge
