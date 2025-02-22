from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime,timedelta,timezone
from jose import JWTError,jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from databases import Database

DATABASE_URL = "postgresql://users_m3y4_user:iknKw3tw6VblFtKmv3voE3x9bh1CFXnT@dpg-custu6rqf0us739p7edg-a/users_m3y4" 

SECRET_KEY = "b18a7e6fe1a7ed5446f9614ccb1c89a8da126d066ee72960bcba51f58ef150b7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



db = {
     "tim": {
         "username": "tim",
         "full_name": "Tim Rusca",
         "email": "tim@gmail.com",
         "hashed_password": "$2b$12$WCg33YIXPQbkh79krt6WP.y1Y2nNOUvhnjXcIanuaqit3ajlJJMY6",
         "disabled": False
     }
 }

class Token(BaseModel):
     access_token:str
     token_type: str

class TokenData(BaseModel):
     username: str | None = None

# class User(BaseModel):
#      username: str
#      email: str | None = None 
#      full_name: str | None = None 
#      disabled: bool | None = None 
    
# class UserInDB(User):
#      hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated= "auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

    
app = FastAPI()     

database = Database(DATABASE_URL)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String)
    disabled = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

class UserInDB(User):
     hashed_password: str
     
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Ή ["*"] για όλους
    allow_credentials=True,
    allow_methods=["*"],  # GET, POST, OPTIONS, κλπ.
    allow_headers=["*"],
)
@app.get("/test")
async def test():
    return {"message": "Hello, World!"}

def verify_password(plain_password, hashed_password):
     return pwd_context.verify(plain_password,hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db,username:str):
     if username in db:
         user_data = db[username]
         return UserInDB(**user_data)

def authenticate_user(db, username:str, password:str):
     user= get_user(db,username)
     if not user:
         return False
     if not verify_password(password,user.hashed_password):
         return False
     return user

def create_access_token(data: dict, expires_delta: timedelta | None=None):
     to_encode = data.copy()
     if expires_delta:
         expire = datetime.now(timezone.utc) + expires_delta
     else:
         expire = datetime.now(timezone.utc) + timedelta(minutes=15)

     to_encode.update({"exp": expire})
     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
     return encoded_jwt

async def get_current_user(token: str = Depends(oauth_2_scheme)):
     credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})
     try:
         payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
         username: str = payload.get("sub")
         if username is None:
             raise credential_exception
         token_data = TokenData(username=username)
     except JWTError:
         raise credential_exception
    
     user = get_user(db, username=token_data.username)
     if user is None:
         raise credential_exception
     return user

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
     if current_user.disabled:
         raise HTTPException(status_code=400, detail="Inactive user")

     return current_user    

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm= Depends()):
     user = authenticate_user(db, form_data.username, form_data.password)
     if not user:
         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate":"Bearer"})

     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES) 
     access_token = create_access_token(data={"sub":user.username}, expires_delta= access_token_expires)       
     return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
     return current_user

@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
     return [{"item_id":1, "owner": current_user}]

