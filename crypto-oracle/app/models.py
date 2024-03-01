from pydantic import BaseModel
from webauthn.helpers.structs import AuthenticatorTransport
from typing import Dict, List, Optional, Tuple, Union
from base64 import urlsafe_b64encode


class base64url:
    def encode(byte_array):
        return urlsafe_b64encode(byte_array).rstrip(b"=").decode()


class Credential(BaseModel):
    id: str
    raw_id: bytes
    public_key: bytes
    sign_count: int
    transports: Optional[List[AuthenticatorTransport]] = None


class UserAccount(BaseModel):
    id: str
    raw_id: bytes
    name: str
    credentials: List[Credential] = []


class VerificationResult(BaseModel):
    verified: Union[bool, None]
    username: Optional[str] = None
    details: Optional[Dict] = None


def get_user_credential(
    database: Dict[str, UserAccount], user_account_id: str, credentials_id: str
) -> Optional[Tuple[str, Credential]]:
    for user in database.values():
        if user.id == user_account_id:
            for credential in user.credentials:
                if credential.id == credentials_id:
                    return user.name, credential
    return None
