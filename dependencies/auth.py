import os
from typing import Optional
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from database import engine
from model import User
from schemas import TokenData
from dotenv import load_dotenv

load_dotenv()

ACCESS_TOKEN_SECRET = os.environ['ACCESS_TOKEN_SECRET']
REFRESH_TOKEN_SECRET = os.environ['REFRESH_TOKEN_SECRET']
JWT_ALGORITHM = os.environ['JWT_ALGORITHM']

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str):
    with Session(engine) as session:
        results = session.query(User).filter(User.username == username)
        user = results.first()

        if not user:
            return False
        if not verify_password(password, user.password):
            return False
        return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, ACCESS_TOKEN_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    with Session(engine) as session:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, ACCESS_TOKEN_SECRET,
                                 algorithms=[JWT_ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
            token_data = TokenData(username=username)
        except JWTError:
            raise credentials_exception
        results = session.query(User).filter(
            User.username == token_data.username)
        user = results.first()
        if user is None:
            raise credentials_exception
        return user


def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user
