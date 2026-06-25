import re
from urllib.parse import quote

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
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
async def login_page(request: Request, error: str = None):
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": error}
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
        .select("username, password")
        .or_(f"username.eq.{login},gmail.eq.{login}")
        .limit(1)
        .execute()
    )

    if not result.data:
        return RedirectResponse(
            "/login?error=" + quote("Username atau Gmail tidak ditemukan"),
            status_code=303
        )

    user = result.data[0]

    if not verify_password(password, user["password"]):
        return RedirectResponse(
            "/login?error=" + quote("Password salah"),
            status_code=303
        )

    # kirim username ke dashboard
    return RedirectResponse(
        f"/dashboard?login={user['username']}",
        status_code=303
    )
# =========================
# REGISTER PAGE
# =========================
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, error: str = None):
    return templates.TemplateResponse(
        "register.html",
        {"request": request, "error": error}
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

    if len(password) < 8:
        return RedirectResponse(
            "/register?error=" + quote("Password minimal 8 karakter"),
            status_code=303
        )

    if not re.search(r"[A-Za-z]", password):
        return RedirectResponse(
            "/register?error=" + quote("Password harus mengandung huruf"),
            status_code=303
        )

    if not re.search(r"\d", password):
        return RedirectResponse(
            "/register?error=" + quote("Password harus mengandung angka"),
            status_code=303
        )

    if password != confirm_password:
        return RedirectResponse(
            "/register?error=" + quote("Konfirmasi password tidak cocok"),
            status_code=303
        )

    existing_username = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if existing_username.data:
        return RedirectResponse(
            "/register?error=" + quote("Username sudah digunakan"),
            status_code=303
        )

    existing_gmail = (
        supabase.table("users")
        .select("id")
        .eq("gmail", gmail)
        .limit(1)
        .execute()
    )

    if existing_gmail.data:
        return RedirectResponse(
            "/register?error=" + quote("Gmail sudah terdaftar"),
            status_code=303
        )

    supabase.table("users").insert({
        "gmail": gmail,
        "username": username,
        "password": hash_password(password),
        "saldo": 0
    }).execute()

    # ambil username untuk dashboard
    return RedirectResponse(
        f"/dashboard?login={username}",
        status_code=303
    )


# =========================
# DASHBOARD
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, login: str = None):
    if not login:
        return RedirectResponse("/login")
    user_res = (
        supabase
        .table("users")
        .select("*")
        .or_(f"username.eq.{login},gmail.eq.{login}")
        .limit(1)
        .execute()
    )
    if not user_res.data:
        return RedirectResponse("/login")
    user = user_res.data[0]
    user_id = user["id"]
    # LINKS USER
    links_res = (
        supabase
        .table("links")
        .select("*")
        .eq("user_id", user_id)
        .execute()
    )
    links = links_res.data or []
    total_links = len(links)
    total_clicks = sum(
        int(link.get("clicks", 0))
        for link in links
    )
    total_link_earnings = sum(
        int(link.get("earnings", 0))
        for link in links
    )
    # RECENT ACTIVITY
    recent_links = (
        supabase
        .table("links")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(10)
        .execute()
    ).data or []
    # ANNOUNCEMENT
    announcement = (
        supabase
        .table("announcements")
        .select("*")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    ).data
    announcement_text = ""
    if announcement:
        announcement_text = announcement[0]["content"]
    # GLOBAL CHAT
    chat_messages = (
        supabase
        .table("chat_messages")
        .select("*")
        .order("created_at", desc=True)
        .limit(30)
        .execute()
    ).data or []
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "username": user["username"],
            "saldo": user.get("saldo", 0),
            "total_earn": user.get("total_earn", 0),
            "referrals": user.get("referrals", 0),
            "total_links": total_links,
            "total_clicks": total_clicks,
            "total_link_earnings": total_link_earnings,
            "announcement": announcement_text,
            "recent_links": recent_links,
            "chat_messages": chat_messages
        }
    )
# =========================
# FAVICON (IGNORE ERROR LOG)
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
