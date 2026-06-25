from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from database import supabase
from auth import hash_password, verify_password

app = FastAPI()
templates = Jinja2Templates(directory="templates")


# =========================
# HOME
# =========================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )
# =========================
# LOGIN PAGE
# =========================
@app.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    error: str = None
):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": error
        }
    )
# =========================
# LOGIN REAL
# =========================
@app.post("/login")
def login_post(
    login: str = Form(...),
    password: str = Form(...)
):
    result = (
        supabase
        .table("users")
        .select("*")
        .or_(f"username.eq.{login},gmail.eq.{login}")
        .execute()
    )

    if not result.data:
        return RedirectResponse(
            url="/login?error=Username atau Gmail tidak ditemukan",
            status_code=303
        )

    user = result.data[0]

    if not verify_password(password, user["password"]):
        return RedirectResponse(
            url="/login?error=Password salah",
            status_code=303
        )

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )
# =========================
# REGISTER PAGE
# =========================
@app.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    error: str = None
):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "error": error
        }
    )


# =========================
# REGISTER REAL
# =========================
import re
from urllib.parse import quote

@app.post("/register")
def register_post(
    gmail: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):

    if len(password) < 8:
        return RedirectResponse(
            url=f"/register?error={quote('Password minimal 8 karakter')}",
            status_code=303
        )

    if not re.search(r"[A-Za-z]", password):
        return RedirectResponse(
            url=f"/register?error={quote('Password harus mengandung huruf')}",
            status_code=303
        )

    if not re.search(r"\d", password):
        return RedirectResponse(
            url=f"/register?error={quote('Password harus mengandung angka')}",
            status_code=303
        )

    if password != confirm_password:
        return RedirectResponse(
            url=f"/register?error={quote('Konfirmasi password tidak cocok')}",
            status_code=303
        )

    existing_username = (
        supabase
        .table("users")
        .select("*")
        .eq("username", username)
        .execute()
    )

    if existing_username.data:
        return RedirectResponse(
            url=f"/register?error={quote('Username sudah digunakan')}",
            status_code=303
        )

    existing_gmail = (
        supabase
        .table("users")
        .select("*")
        .eq("gmail", gmail)
        .execute()
    )

    if existing_gmail.data:
        return RedirectResponse(
            url=f"/register?error={quote('Gmail sudah terdaftar')}",
            status_code=303
        )

    try:
        supabase.table("users").insert({
            "gmail": gmail,
            "username": username,
            "password": hash_password(password)
        }).execute()

    except Exception:
        return RedirectResponse(
            url=f"/register?error={quote('Gagal membuat akun')}",
            status_code=303
        )

    return RedirectResponse(
        url="/login",
        status_code=303
    )
# =========================
# DASHBOARD
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html"
    )
