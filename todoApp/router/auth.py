from fastapi import FastAPI,APIRouter
from pydantic import BaseModel
from models import Users
from passlib.context import CryptContext
from typing import Annotated
from database import sessionLocal
from sqlalchemy.orm import Session
from fastapi import APIRouter,Depends
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from jose import jwt
from datetime import timedelta,datetime

router=APIRouter()

SECRET_KEY="51e32298882b8fa67040eb2e49ae472c174f3e991e23981d10ce6f84303b276b"
ALGORITHM='HS256'



bcrypt_context=CryptContext(schemes=['bcrypt'],deprecated='auto')


class Token(BaseModel):
    access_token: str
    token_type: str









class CreateUserRequest(BaseModel):
    username:str
    email:str
    first_name:str
    password:str
    role:str
    last_name:str


def get_db():
    db=sessionLocal()
    print(db)
    try:
        yield db

    finally:
        db.close()

db_dependency=Annotated[Session,Depends(get_db)]


def authenticate_user(username: str, password: str,db):
    user=db.query(Users).filter(Users.username==username).first()
    if not user:
        return False

    if not bcrypt_context.verify(password,user.hashed_password):
        return False

    return user


def create_access_token(username:str,user_id: int, expires_delta:timedelta):
    encode={'sub':username,'id':user_id}
    expires=datetime.utcnow()+expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)



@router.post("/auth/",status_code=status.HTTP_201_CREATED)
async def create_user(db:db_dependency,create_user_request:CreateUserRequest):
    create_user_model=Users(
        email=create_user_request.email,
        username=create_user_request.username,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        role=create_user_request.role,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        is_active=True
    )

    db.add(create_user_model)
    db.commit()


    return create_user_model

@router.post("/token",response_model=Token)
async def login_for_access_token(form_data:Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependency):

    user=authenticate_user(form_data.username,form_data.password,db)
    if not user:
        return "fail"

    token=create_access_token(user.username,user.id,timedelta(minutes=20))
    return {'access_token': token, "token_type": 'bearer'}