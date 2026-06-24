from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session

from database import Base, engine, SessionLocal
from models import User
from auth import hash_password, verify_password

app = FastAPI()
templates = Jinja2Templates(directory="templates")


# =========================
# INIT DB
# =========================
Base.metadata.create_all(bind=engine)


# =========================
# DB SESSION
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# HOME
# =========================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


# =========================
# LOGIN PAGE
# =========================
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


# =========================
# LOGIN REAL (DATABASE)
# =========================
@app.post("/login")
def login_post(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(User.username == username).first()

    if not user:
        return HTMLResponse("User tidak ditemukan", status_code=404)

    if not verify_password(password, user.password):
        return HTMLResponse("Password salah", status_code=401)

    return RedirectResponse("/dashboard", status_code=303)


# =========================
# REGISTER PAGE
# =========================
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request}
    )


# =========================
# REGISTER REAL (DATABASE)
# =========================
@app.post("/register")
def register_post(
    gmail: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):

    if password != confirm_password:
        return HTMLResponse("Password tidak sama", status_code=400)

    # cek user sudah ada
    existing = db.query(User).filter(
        (User.username == username) | (User.gmail == gmail)
    ).first()

    if existing:
        return HTMLResponse("User sudah terdaftar", status_code=400)

    new_user = User(
        gmail=gmail,
        username=username,
        password=hash_password(password)
    )

    db.add(new_user)
    db.commit()

    return RedirectResponse("/login", status_code=303)


# =========================
# DASHBOARD
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request}
    )
