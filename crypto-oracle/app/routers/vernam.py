from base64 import b64encode

from fastapi import APIRouter, Depends

from app.config import get_app_settings, vernam
from app.crypto import Ciphertext, VernamPlaintext, derive_key, xor_cipher
from app.dependencies import (
    RouteCredentials,
    Token,
    get_token_for_route,
    validate_scope,
)

router = APIRouter(prefix=vernam.prefix, tags=["VERNAM"])

route_credentials = RouteCredentials(scope=vernam.scope, password=vernam.password)
validate_access = validate_scope(scope=vernam.scope)
settings = get_app_settings()

key = derive_key(key_seed=settings.key_seed, key_length=vernam.key_size)
# repeat the key to make it as long as the challenge
challenge = vernam.challenge.encode()
keystream = key * (len(challenge) // vernam.key_size + 1)
challenge = xor_cipher(keystream, challenge)


@router.post("/token", response_model=Token)
def get_token(token: Token = Depends(get_token_for_route(route_credentials))):
    return token


@router.post("/", dependencies=[Depends(validate_access)], response_model=Ciphertext)
def encrypt_plaintext(plaintext: VernamPlaintext):
    global key
    plaintext = plaintext.plaintext.encode()
    keystream = key * (len(plaintext) // vernam.key_size + 1)
    ciphertext = xor_cipher(key=keystream, input=plaintext)

    return Ciphertext(ciphertext=b64encode(ciphertext))


@router.get("/challenge", response_model=Ciphertext)
def read_challenge():
    return Ciphertext(ciphertext=b64encode(challenge))
