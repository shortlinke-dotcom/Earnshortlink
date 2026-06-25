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
# LOGIN REAL
# =========================
@app.post("/login")
def login_post(
    username: str = Form(...),
    password: str = Form(...)
):
    result = (
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .execute()
    )

    if not result.data:
        return HTMLResponse(
            "User tidak ditemukan",
            status_code=404
        )

    user = result.data[0]

    if not verify_password(password, user["password"]):
        return HTMLResponse(
            "Password salah",
            status_code=401
        )

    return RedirectResponse(
        "/dashboard",
        status_code=303
    )


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
# REGISTER REAL
# =========================
@app.post("/register")
def register_post(
    gmail: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    if password != confirm_password:
        return HTMLResponse(
            "Password tidak sama",
            status_code=400
        )

    existing = (
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .execute()
    )

    if existing.data:
        return HTMLResponse(
            "Username sudah digunakan",
            status_code=400
        )

    supabase.table("users").insert({
        "gmail": gmail,
        "username": username,
        "password": hash_password(password)
    }).execute()

    return RedirectResponse(
        "/login",
        status_code=303
    )


# =========================
# DASHBOARD
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request}
    )
