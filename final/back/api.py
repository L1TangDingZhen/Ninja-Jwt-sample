from datetime import datetime, timedelta

from ninja import NinjaAPI
from back.scheme import User, NoMessage, LoginSuccess
from back.models import user
from typing import List
from ninja.security import django_auth, HttpBearer
from ninja.errors import HttpError
from jose import jwt
from ninja_jwt.controller import NinjaJWTDefaultController
from ninja_extra import NinjaExtraAPI
# config.py
import os
import secrets
import string


# from config import JWT_SECRET_KEY
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 43200


class GlobalAuth(HttpBearer):
    def authenticate(self, request, token):
        if token == "supersecret":
            return token


# api = NinjaAPI(auth=GlobalAuth()) #全局验证
api = NinjaExtraAPI() #多出来一个token验证类
api.register_controllers(NinjaJWTDefaultController)


# 生成一个随机字符串作为密钥
alphabet = string.ascii_letters + string.digits
secret_key = ''.join(secrets.choice(alphabet) for i in range(32))

# 如果环境变量中有 JWT_SECRET_KEY,就使用环境变量的值
# 否则,使用上面生成的随机字符串
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secret_key)


# def generate_token(username: str, expires_delta = None):
#     to_encode = {"sub": username}.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#         to_encode.update({"exp": expires_delta})
#     else:
#         expire = datetime.utcnow() + datetime.timedelta(minutes=15)
#     to_encode.update(dict(exp=expire))
#     encoded_jwt = jwt.encode(to_encode, "secret", algorithm="HS256")
#     return encoded_jwt



# class AuthBearer(HttpBearer):
#     def authenticate(self, request, token):
#         if token == "supersecret":
#             return token

class AuthBearer(HttpBearer):
    def authenticate(self, request, token):
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            username = payload["sub"]
            exp = payload["exp"]
            if datetime.utcnow() < datetime.utcfromtimestamp(exp):
                return username
            else:
                # 如果令牌已过期，生成一个新的令牌
                new_exp = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
                new_token = jwt.encode({"sub": username, "exp": new_exp}, JWT_SECRET_KEY, algorithm="HS256")
                request.headers["Authorization"] = f"Bearer {new_token}"
                return username
        except jwt.JWTError:
            raise HttpError(401, "Invalid token")

# @api.post('/refresh_token', response={200: LoginSuccess}, auth=AuthBearer())
# def refresh_token(request):
#     try:
#         payload = jwt.decode(request.auth, JWT_SECRET_KEY, algorithms=["HS256"])
#         username = payload["sub"]
#         expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
#         new_token = jwt.encode({"sub": username, "exp": expire}, JWT_SECRET_KEY, algorithm="HS256")
#         return {"username": username, "token": new_token}
#     except jwt.JWTError:
#         raise HttpError(401, "Invalid or expired token")
    


@api.post('/register', response={201: User}, auth=None)
def register(request, info: User):
    if user.objects.filter(username=info.username).exists():
        return NoMessage(message="username already exists")
    user.objects.create(username=info.username, password=info.password)
    return 201, {"message": "OK"}



@api.post('/login', response={200: LoginSuccess}, auth=None)
def login(request, info: User):
    if user.objects.filter(username=info.username, password=info.password).exists():
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        token = jwt.encode({"sub": info.username, "exp": expire}, JWT_SECRET_KEY, algorithm="HS256")
        return {"username": info.username, "token": token}
    return 401, {"message": "username or password is wrong"}




@api.get('/num', response={200: List[User]}, auth=AuthBearer())
def mmm(request):
    return 200, list(user.objects.all().values())