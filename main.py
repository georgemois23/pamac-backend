from fastapi import Depends, FastAPI, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker, Session, declarative_base  # Updated import
import os
from dotenv import load_dotenv
from fastapi.security.api_key import APIKeyHeader
import schedule
import time
import threading
import httpx
from fastapi import FastAPI
from contextlib import asynccontextmanager

# Φόρτωση .env αρχείου
load_dotenv()

IS_LOCAL = os.getenv("ENV") == "local"
print("ENV:", os.getenv("ENV"))


SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


# Ρύθμιση σύνδεσης με τη βάση δεδομένων
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()  # No change here, but import is fixed

# Ορισμός User Model για τη βάση δεδομένων
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String)
    disabled = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# Ρυθμίσεις ασφαλείας
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI app
app = FastAPI(
    lifespan=lifespan,
    docs_url="/docs" if IS_LOCAL else None,  # Disable in production
    redoc_url="/redoc" if IS_LOCAL else None
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Keep localhost for local development
        "https://pamac.moysiadis.codes"  # Add your deployed frontend URL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
    except JWTError:
        raise credential_exception

    user = get_user(db, username)
    if user is None:
        raise credential_exception
    return user

async def get_current_active_user(current_user: UserDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Pydantic models
class User(BaseModel):
    id: int
    username: str
    email: str
    full_name: str | None = None
    disabled: bool = False

    class Config:
        from_attributes = True  # Changed to match Pydantic V2


def ping_server():
    try:
        with httpx.Client() as client:
            response = client.get("https://pamac-backendd.onrender.com/ping")
            print("Ping response:", response.status_code)
    except Exception as e:
        print("Ping failed:", e)

# Set ping interval to 14 minutes
schedule.every(14).minutes.do(ping_server)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

# Use the new `lifespan` method
@asynccontextmanager
async def lifespan(app: FastAPI):
    thread = threading.Thread(target=run_scheduler, daemon=True)
    thread.start()
    yield  # Continue app startup
    # Cleanup code can go here if needed

@app.get("/ping")
async def ping():
    return {"status": "alive"}


# Routes
@app.get("/test")
async def test():
    return {"message": "Hello, World!"}

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

@app.post("/token", response_model=TokenResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Check if user credentials are valid
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if the token has expired or is missing, and generate a new token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}

# Or a refresh token flow
@app.post("/refresh-token", response_model=TokenResponse)
async def refresh_access_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Decode and verify the token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Now that the token is valid, you can generate a new one
    user = get_user(db, username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate a new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}


class UserRegister(BaseModel):
    username: str
    password: str
    email: str = ""
    full_name: str = ""

@app.post("/register")
def register_user(user: UserRegister, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = UserDB(username=user.username, email=user.email, full_name=user.full_name, hashed_password=hashed_password)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User registered successfully"}



# @app.post("/token", response_model=BaseModel)
# async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
#     user = authenticate_user(db, form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
#     return {"access_token": access_token, "token_type": "bearer"}



@app.get("/users/me/items")
async def read_own_items(current_user: UserDB = Depends(get_current_active_user)):
    return [{"item_id": 1, "owner": current_user.username}]

import logging

logger = logging.getLogger("uvicorn.error")

@app.get("/users/me/")
async def read_users_me(current_user: UserDB = Depends(get_current_user)):
    logger.info(f"Fetching user data for: {current_user.username}")
    try:
        return User(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        disabled=current_user.disabled
    )
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
# @app.get("/users/me", response_model=User)
# async def read_users_me(current_user: UserDB = Depends(get_current_active_user)):
#     return current_user