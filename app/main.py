from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from .db import Base, engine, get_db, SessionLocal
from .models import User, Note
from .schemas import LoginRequest, TokenResponse, UserOut, NoteCreate, NoteOut
from .auth import verify_password, hash_password, create_access_token, get_current_user
from .security_headers import InsecureHeadersMiddleware

def seed(db: Session):
    if db.query(User).count() == 0:
        alice = User(username='alice', password_hash=hash_password('password123'))
        bob = User(username='bob', password_hash=hash_password('hunter2'))
        db.add_all([alice, bob])
        db.commit()
        db.add_all([
            Note(owner_id=alice.id, content="Alice's secret note"),
            Note(owner_id=bob.id, content="Bob's shopping list")
        ])
        db.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()
    yield
    # Shutdown

app = FastAPI(
    title='Vulnerable FastAPI Demo',
    description='Demo app for DAST testing with authentication',
    version='1.0.0'
)
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
app.add_middleware(InsecureHeadersMiddleware)

@app.post('/auth/login', response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = create_access_token(sub=user.username)
    return TokenResponse(access_token=token)

@app.get('/users', response_model=list[UserOut])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.get('/users/search', response_model=list[UserOut])
def search_users_vulnerable(username: str = Query(''), db: Session = Depends(get_db)):
    raw_sql = f"SELECT id, username, password_hash FROM users WHERE username LIKE '%{username}%'"
    rows = db.execute(text(raw_sql))
    return [{"id": r[0], "username": r[1]} for r in rows.fetchall()]

@app.get('/me', response_model=UserOut, summary="Get current user info")
def me(current_user: User = Depends(get_current_user)):
    """Get information about the currently authenticated user."""
    return UserOut(id=current_user.id, username=current_user.username)

@app.get('/notes', response_model=list[NoteOut])
def list_notes(current=Depends(get_current_user), db: Session = Depends(get_db)):
    notes = db.query(Note).filter(Note.owner_id == current.id).all()
    return [NoteOut.model_validate(n) for n in notes]

@app.post('/notes', response_model=NoteOut)
def create_note(note: NoteCreate, current=Depends(get_current_user), db: Session = Depends(get_db)):
    n = Note(owner_id=current.id, content=note.content)
    db.add(n)
    db.commit()
    db.refresh(n)
    return NoteOut.model_validate(n)
