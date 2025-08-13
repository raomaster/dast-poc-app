from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
import os
from pathlib import Path
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

# VULNERABILIDAD: Configuración CORS insegura - permite solicitudes desde cualquier origen
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

# VULNERABILIDAD: Headers de seguridad insuficientes - faltan headers importantes como Content-Security-Policy
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

# VULNERABILIDAD: SQL Injection - concatenación directa de entrada del usuario en consulta SQL
@app.get('/users/search', response_model=list[UserOut])
def search_users_vulnerable(username: str = Query(''), db: Session = Depends(get_db)):
    # Vulnerable a SQL Injection: la entrada del usuario se concatena directamente en la consulta SQL
    # Ejemplo de explotación: ?username=a'%20OR%201=1%20--%20
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

# VULNERABILIDAD: Cross-Site Scripting (XSS) - renderizado inseguro de contenido proporcionado por el usuario
@app.get('/render', response_class=HTMLResponse)
def render_html(content: str = Query("")):
    # Vulnerable a XSS: el contenido proporcionado por el usuario se renderiza directamente como HTML
    # Ejemplo de explotación: ?content=<script>alert('XSS')</script>
    return f"<html><body>{content}</body></html>"

# VULNERABILIDAD: Path Traversal - acceso inseguro a archivos del sistema
@app.get('/files/{file_path:path}')
def get_file(file_path: str):
    # Vulnerable a Path Traversal: permite acceder a cualquier archivo del sistema
    # Ejemplo de explotación: /files/../../../etc/passwd
    base_dir = Path("./static")
    file = base_dir / file_path
    
    try:
        with open(file, 'r') as f:
            content = f.read()
        return {"content": content}
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"File not found: {str(e)}")
