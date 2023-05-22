from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

# local host  http://127.0.0.1:8000/


ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 1
SECRET = "efe83f9951e9ca10c1f7c91a10684458b9d0057d186408fef700fa2d241ae7a1"

app = FastAPI()
oauth2 = OAuth2PasswordBearer(tokenUrl="login")

# password hashing
crypt = CryptContext(schemes=["bcrypt"], deprecated = "auto")

# definicion de clase
class User(BaseModel):
    username: str
    password: str



users_db = []

# verificacion del password

def verify_password(original_password, hashed_password):
    return crypt.verify(original_password, hashed_password)

# encriptacion del password

def get_password_hash(password):
    return crypt.hash(password)

def get_user(username: str):
    for user in users_db:
        if user["username"] == username:
            return user

# autenticacion del usuario

def authenticate_user(username: str, password: str):
    userdb = get_user(username)
    if not userdb:
        return False
    if not verify_password(password, userdb["password"]):
        return False
    return userdb

# creacion del token encriptado

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)
    return encoded_jwt

# verificacion del token

def token_verify(token: str = Depends(oauth2)):
    try:
        token_verificacion = jwt.decode(token, SECRET, algorithms=[ALGORITHM])
        username = token_verificacion.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return {"message": f"Bienvenido, {username}!"}

# registro de usuario

@app.post("/register")
async def register_user(user: User):
    
    if any(u['username'] == user.username for u in users_db):
        return {"message": "El usuario ya está registrado"}
    
    hashed_password = get_password_hash(user.password)
    user = {"username": user.username, "password": hashed_password}
    users_db.append(user)
    
    return {"message": "Usuario registrado exitosamente"}

# login con verificacion

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_DURATION)
    access_token = create_access_token(data={"sub": user["username"]}, expires_delta=access_token_expires)
    return token_verify(access_token)


# listado de usuarios

@app.get("/lista")
async def users():
    return users_db