from typing import Dict
from pathlib import Path
from typing_extensions import Annotated

from fastapi import APIRouter, Body, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr
from uuid import uuid4
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)
from app.config import passkeys
from app.models import (
    base64url,
    Credential,
    UserAccount,
    VerificationResult,
    get_user_credential,
)
from devtools import pprint
import logging

logger = logging.getLogger("uvicorn")

router = APIRouter(prefix=passkeys.prefix, tags=["Passwordless authentication"])

BASE_PATH = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_PATH / ".." / "templates"))


# Faking DB to persist user credentials
in_memory_db: Dict[str, UserAccount] = {}
current_user: UserAccount = None
logged_in_user: UserAccount = None
current_registration_challenge = None
current_authentication_challenge = None


@router.get("/", response_class=HTMLResponse)
async def register_ui(request: Request):
    return templates.TemplateResponse(
        "signupin.html",
        {
            "request": request,
            "title": "Passwordless authentication",
        },
    )


@router.get("/signin-autofill", response_class=HTMLResponse)
async def autofill_ui(request: Request):
    return templates.TemplateResponse(
        "signin.html",
        {
            "request": request,
            "title": "Passwordless authentication",
        },
    )


@router.post("/register/", response_model=str)
def get_registration_options(email: Annotated[EmailStr, Form()], request: Request):
    global current_user
    global current_registration_challenge

    if in_memory_db.get(email) is not None:
        raise HTTPException(status_code=401, detail="User already registered.")

    raw_id = uuid4().bytes
    current_user = UserAccount(id=base64url.encode(raw_id), raw_id=raw_id, name=email)

    options = generate_registration_options(
        rp_id=request.base_url.hostname,
        rp_name=passkeys.rp_name,
        user_id=current_user.raw_id,
        user_name=current_user.name,
    )

    current_registration_challenge = options.challenge

    return options_to_json(options)


@router.post("/register/verify/", response_model=VerificationResult)
async def verify_registration(request: Request, credential: dict = Body()):
    global current_user
    global current_registration_challenge

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=current_registration_challenge,
            expected_rp_id=request.base_url.hostname,
            expected_origin=str(request.base_url).rstrip("/"),
        )
    except Exception as e:
        logger.error(e)
        raise HTTPException(status_code=400, detail="Verification failed")

    raw_id = verification.credential_id
    current_user.credentials.append(
        Credential(
            id=base64url.encode(raw_id),
            raw_id=raw_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            transports=credential.get("transports", []),
        ),
    )

    in_memory_db[current_user.name] = current_user
    response = VerificationResult(verified=True, username=current_user.name)
    pprint(in_memory_db)
    current_user = None

    return response


@router.post("/login/")
def get_login_options(email: Annotated[EmailStr, Form()], request: Request):
    global logged_in_user
    global current_authentication_challenge

    try:
        logged_in_user = in_memory_db[email]
    except KeyError:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    options = generate_authentication_options(
        rp_id=request.base_url.hostname,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=cred.raw_id, transports=cred.transports)
            for cred in logged_in_user.credentials
        ],
    )

    current_authentication_challenge = options.challenge

    return options_to_json(options)


@router.post("/login/verify/", response_model=VerificationResult)
def verify_login(request: Request, credential: dict = Body()):
    global logged_in_user
    global current_authentication_challenge

    if logged_in_user is None:
        raise HTTPException(status_code=400, detail="Invalid request.")

    try:
        user_credential = None
        for _cred in logged_in_user.credentials:
            if _cred.id == credential.get("id"):
                user_credential = _cred

        if user_credential is None:
            raise HTTPException(status_code=400, detail="Missing public key")

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=current_authentication_challenge,
            expected_rp_id=request.base_url.hostname,
            expected_origin=str(request.base_url).rstrip("/"),
            credential_public_key=user_credential.public_key,
            credential_current_sign_count=user_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as e:
        logger.error(e)
        raise HTTPException(status_code=400, detail="Login verification failed")

    user_credential.sign_count = verification.new_sign_count
    pprint(in_memory_db)

    return VerificationResult(verified=True, username=logged_in_user.name)


@router.post("/login-autofill/")
def get_login_options_autofill(request: Request):
    global current_authentication_challenge

    options = generate_authentication_options(
        rp_id=request.base_url.hostname,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    current_authentication_challenge = options.challenge

    return options_to_json(options)


@router.post("/login-autofill/verify/", response_model=VerificationResult)
async def verify_login_autofill(request: Request, credential: dict = Body()):
    global current_authentication_challenge

    try:
        username, user_credential = get_user_credential(
            database=in_memory_db,
            user_account_id=credential.get("response").get("userHandle"),
            credentials_id=credential.get("id"),
        )

        if user_credential is None or user_credential.public_key is None:
            raise Exception()

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=current_authentication_challenge,
            expected_rp_id=request.base_url.hostname,
            expected_origin=str(request.base_url).rstrip("/"),
            credential_public_key=user_credential.public_key,
            credential_current_sign_count=user_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as e:
        logger.error(e)
        raise HTTPException(status_code=400, detail="Login verification failed")

    user_credential.sign_count = verification.new_sign_count
    pprint(in_memory_db)

    return VerificationResult(verified=True, username=username)
