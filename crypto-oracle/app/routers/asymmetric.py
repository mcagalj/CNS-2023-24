from base64 import b64decode, b64encode
from fastapi import APIRouter, Depends, HTTPException
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import get_app_settings, asymmetric
from app.dependencies import (
    Token,
    RouteCredentials,
    get_token_for_route,
    validate_scope,
)

from app.crypto import (
    Challenge,
    PublicKey,
    RSAandDHParams,
    SignedPublicKey,
    encrypt_challenge,
)

router = APIRouter(prefix="/asymmetric", tags=["Asymmetric Cryptography"])

settings = get_app_settings()
route_credentials = RouteCredentials(
    scope=asymmetric.scope, password=asymmetric.password
)
validate_access = validate_scope(scope=asymmetric.scope)

server_RSA_private = rsa.generate_private_key(
    public_exponent=65537, key_size=asymmetric.key_size
)
server_RSA_public_serialized = server_RSA_private.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
dh_parameters = dh.generate_parameters(generator=2, key_size=asymmetric.key_size)
dh_parameters_serialized = dh_parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
)
server_DH_private = None
client_RSA_public = None
client_DH_public = None


@router.post("/token", response_model=Token)
def get_token(token: Token = Depends(get_token_for_route(route_credentials))):
    return token


@router.post(
    "/exchange/rsa-dh-params",
    dependencies=[Depends(validate_access)],
    response_model=RSAandDHParams,
)
def exchange_rsa_keys(client_key: PublicKey):
    global client_RSA_public

    try:
        client_RSA_public_serialized = client_key.key.encode()
        client_RSA_public = serialization.load_pem_public_key(
            client_RSA_public_serialized
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=repr(error))

    return RSAandDHParams(
        key=server_RSA_public_serialized, dh_params=dh_parameters_serialized
    )


@router.post(
    "/exchange/dh",
    dependencies=[Depends(validate_access)],
    response_model=SignedPublicKey,
)
def exchange_signed_dh_keys(client_key: SignedPublicKey):
    global server_DH_private
    global client_DH_public

    if not client_RSA_public:
        raise HTTPException(status_code=400, detail="Missing client's RSA key.")

    try:
        # 1. Verify the signature over client_DH_public key
        client_RSA_public.verify(
            signature=b64decode(client_key.signature),
            data=client_key.key.encode(),
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256(),
        )

        # 2. Deserialize client_DH_public
        client_DH_public_serialized = client_key.key.encode()
        client_DH_public = serialization.load_pem_public_key(
            client_DH_public_serialized
        )

        # 3. Generate server_DH key pair
        server_DH_private = dh_parameters.generate_private_key()
        server_DH_public_serialized = server_DH_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # 4. Sign (DH params || server DH public key || client DH public key) with server's RSA private key
        signature = server_RSA_private.sign(
            data=dh_parameters_serialized
            + server_DH_public_serialized
            + client_DH_public_serialized,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256(),
        )

        signature_serialized = b64encode(signature)
    except Exception as error:
        raise HTTPException(status_code=400, detail=repr(error))

    return SignedPublicKey(
        dh_parameters=dh_parameters_serialized,
        key=server_DH_public_serialized,
        signature=signature_serialized,
    )


@router.get("/challenge", response_model=Challenge)
def read_challenge():
    if not client_DH_public:
        raise HTTPException(status_code=400, detail="Missing client's public DH key.")

    if not server_DH_private:
        raise HTTPException(
            status_code=400,
            detail="Something went wrong. Re-run the protocol from start.",
        )

    # 1. Calculate a shared DH key
    shared_secret = server_DH_private.exchange(client_DH_public)

    # 2. Perform key derivation
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"ServerClient", info=None
    ).derive(shared_secret)

    # 3. Encrypt the challenge using the derived key
    challenge = encrypt_challenge(key, asymmetric.challenge)
    return challenge
