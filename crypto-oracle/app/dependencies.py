from datetime import UTC, datetime, timedelta
from typing import List, Literal, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordRequestForm,
)
from jose import JWTError, jwt
from pydantic import BaseModel

from .config import get_app_settings

settings = get_app_settings()
token_auth_scheme = HTTPBearer()

class TokenData(BaseModel):
    sub: str
    scope: str

class Token(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"

class RouteCredentials(BaseModel):
    scope: str
    password: str    

def authenticate_user(form_data: OAuth2PasswordRequestForm, route_password: str):
    username = form_data.username
    password = form_data.password
    if not username == settings.app_username:
        return False
    if not password == route_password:
        return False
    return True

def create_token(data: TokenData, expires_delta: Optional[timedelta] = None):
    data_to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=90)
    data_to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        data_to_encode,
        settings.jwt_secret_key, 
        algorithm=settings.jwt_algorithm
    )
    return encoded_jwt

def get_token_for_route(route_credentials: RouteCredentials):
    def get_token(form_data: OAuth2PasswordRequestForm = Depends()):
        authentic = authenticate_user(form_data, route_password=route_credentials.password)

        if not authentic:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )     
        data = TokenData(sub = form_data.username, scope = route_credentials.scope)
        token = create_token(data=data.model_dump())     
        return Token(access_token=token)

    return get_token
    
def validate_token(token: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    token = token.credentials
    try:
        payload = jwt.decode(
            token, 
            settings.jwt_secret_key, 
            algorithms=[settings.jwt_algorithm]
        )
        
        scope = payload.get("scope")
        if not scope:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='The required field "scope" field is missing',
                headers={"WWW-Authenticate": "Bearer"}
            )                            
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return scope        

def validate_scope(scope: str):
    def _validate_scope(token_scope: List[str] = Depends(validate_token)):
        if not scope in token_scope:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f'Invalid scope "{token_scope}" presented (required "{scope}")',
                headers={"WWW-Authenticate": "Bearer"}
            )

    return _validate_scope