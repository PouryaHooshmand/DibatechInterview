from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import pymongo

SECRET_KEY = "add95d1d1a2bb514776a3601b73f9228e65fd7387b5aaedde706b7c173d4864a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15



client = pymongo.MongoClient()
test_db = client.test

users_db = test_db.auth

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str


class UserInDB(User):
    hashed_password: str

class ResetPasswordData(BaseModel):
    old_password: str
    new_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/api_key/")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if db.find_one({"username": username}):
        user_dict = db.find_one({"username": username})
        user_dict.pop('_id', None)
        return UserInDB(**user_dict)


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def validate_username(db, username: str):
    if db.find_one({"username": username}):
        return False
    if (not username.isascii()) or len(username)>32 or len(username)<4:
        return False
    return True


def validate_password(password: str):
    if (not password.isalnum) or len(password)<8:
        return False
    return True


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/api/auth/api_key/", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):

    user = authenticate_user(
        users_db, form_data.username, form_data.password)

    if not user:

        raise HTTPException(

            status_code=status.HTTP_401_UNAUTHORIZED,

            detail="Incorrect username or password",

            headers={"WWW-Authenticate": "Bearer"},

        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_access_token(

        data={"sub": user.username}, expires_delta=access_token_expires

    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/auth/signup/", response_model=Token)
async def signup(form_data: OAuth2PasswordRequestForm = Depends()):

    if not validate_username(users_db, form_data.username):

        raise HTTPException(

            status_code=status.HTTP_401_UNAUTHORIZED,

            detail="Username is taken or has wrong format.",

            headers={"WWW-Authenticate": "Bearer"},

        )

    if not validate_password(form_data.password):

        raise HTTPException(

            status_code=status.HTTP_401_UNAUTHORIZED,

            detail="ٌWrong format for password.",

            headers={"WWW-Authenticate": "Bearer"},

        )

    user = UserInDB(username = form_data.username, hashed_password = pwd_context.hash(form_data.password))

    users_db.insert_one({"username":user.username, "hashed_password": user.hashed_password})

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_access_token(

        data={"sub": form_data.username}, expires_delta=access_token_expires

    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/auth/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/api/users/reset_password/", status_code=200)
async def reset_password(reset_password_data: ResetPasswordData, current_user: User = Depends(get_current_user)):
    user = authenticate_user(
        users_db, current_user.username, reset_password_data.old_password)

    if not user:

        raise HTTPException(

            status_code=status.HTTP_401_UNAUTHORIZED,

            detail="Incorrect password",

            headers={"WWW-Authenticate": "Bearer"},

        )

    if not validate_password(reset_password_data.new_password):
    
        raise HTTPException(

            status_code=status.HTTP_401_UNAUTHORIZED,

            detail="ٌWrong format for password.",

            headers={"WWW-Authenticate": "Bearer"},

        )
    new_password_hashed = pwd_context.hash(reset_password_data.new_password)
    users_db.find_one_and_update({"username":current_user.username}, { "$set":{"hashed_password": new_password_hashed}})
