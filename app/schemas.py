from pydantic import BaseModel
class LoginRequest(BaseModel):
    username:str
    password:str
class TokenResponse(BaseModel):
    access_token:str
    token_type:str='bearer'
class UserOut(BaseModel):
    id:int
    username:str
    class Config:
        from_attributes=True
class NoteCreate(BaseModel):
    content:str
class NoteOut(BaseModel):
    id:int
    content:str
    class Config:
        from_attributes=True
