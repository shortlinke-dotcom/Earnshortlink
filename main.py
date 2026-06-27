import random
import string
import secrets
import os
from datetime import datetime

from fastapi import FastAPI, Request, Form
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    Response
)
from fastapi.templating import Jinja2Templates
from database import supabase
from auth import hash_password, verify_password


app = FastAPI()
templates = Jinja2Templates(directory="templates")

SUPABASE_URL = os.getenv("SUPABASE_URL")
# ======================================================
# HOME
# ======================================================

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

# ======================================================
# LOGIN PAGE
# ======================================================
@app.get("/login")
async def login_page(
    request: Request,
    error: str | None = None
):
    message = None

    if error == "google_not_registered":
        message = "❌ Akun Google ini belum terdaftar. Silakan daftar terlebih dahulu."

    elif error == "notfound":
        message = "❌ Username atau Gmail tidak ditemukan."

    elif error == "wrongpass":
        message = "❌ Password yang Anda masukkan salah."

    elif error == "banned":
        message = "🚫 Akun Anda telah diblokir."

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": message
        }
    )
# ======================================================
# LOGIN
# ======================================================

@app.post("/login")
async def login_post(
    login: str = Form(...),
    password: str = Form(...)
):

    result = (
        supabase.table("users")
        .select("*")
        .eq("gmail", login)
        .limit(1)
        .execute()
    )

    if not result.data:
        return RedirectResponse(
            "/login?error=notfound",
            status_code=303
        )

    user = result.data[0]

    if user.get("is_banned", False):
        return RedirectResponse(
            "/login?error=banned",
            status_code=303
        )

    if not verify_password(password, user["password"]):
        return RedirectResponse(
            "/login?error=wrongpass",
            status_code=303
        )

    return RedirectResponse(
        url=f"/dashboard?login={user['username']}",
        status_code=303
    )
@app.get("/auth/google")
async def auth_google():
    url = (
        f"{SUPABASE_URL}/auth/v1/authorize"
        f"?provider=google"
        f"&redirect_to=https://earnshortlink.up.railway.app/auth/callback"
    )

    print("🔥 AUTH URL:", url)

    return RedirectResponse(url)
    
@app.get("/auth/callback")
async def auth_callback(request: Request):
    print("🔥 CALLBACK HIT:", request.url)
    print("📌 PARAMS:", dict(request.query_params))

    code = request.query_params.get("code")

    if not code:
        print("❌ NO CODE")
        return RedirectResponse(
            "/login?error=google_failed",
            status_code=303
        )

    import requests

    res = requests.post(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=authorization_code",
        headers={
            "apikey": os.getenv("SUPABASE_KEY"),
            "Content-Type": "application/json"
        },
        json={
            "code": code,
            "redirect_uri": "https://earnshortlink.up.railway.app/auth/callback"
        }
    )

    data = res.json()
    print("SUPABASE RESPONSE:", data)

    user = data.get("user")
    if not user:
        return RedirectResponse(
            "/login?error=google_failed",
            status_code=303
        )

    email = user.get("email")

    # cek user sudah terdaftar atau belum
    result = (
        supabase.table("users")
        .select("*")
        .eq("gmail", email)
        .limit(1)
        .execute()
    )

    # jika belum terdaftar
    if not result.data:
        return RedirectResponse(
            f"/setup-username?email={email}",
            status_code=303
        )

    db_user = result.data[0]

    # jika dibanned
    if db_user.get("is_banned", False):
        return RedirectResponse(
            "/login?error=banned",
            status_code=303
        )

    # login ke dashboard
    return RedirectResponse(
        f"/dashboard?login={db_user['username']}",
        status_code=303
    )
# ===============
@app.get("/setup-username")
async def setup_username(request: Request, email: str):

    return templates.TemplateResponse(
        "setup_username.html",
        {
            "request": request,
            "email": email
        }
    )

@app.post("/setup-username")
async def setup_username_post(
    email: str = Form(...),
    username: str = Form(...)
):

    # cek username dipakai
    check = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if check.data:
        return RedirectResponse(
            f"/setup-username?email={email}&error=exists",
            303
        )

    # insert user baru
    supabase.table("users").insert({
        "gmail": email,
        "username": username,
        "password": "",
        "saldo": 0,
        "total_earn": 0,
        "referrals": 0,
        "is_banned": False
    }).execute()

    return RedirectResponse(
        f"/dashboard?login={username}",
        303
    )
# ======================================================
# REGISTER
# ======================================================
@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {"request": request}
    )
@app.post("/register")
async def register_post(
    gmail: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    # Password tidak sama
    if password != confirm_password:
        return RedirectResponse(
            "/register?error=nomatch",
            status_code=303
        )
    # Cek username / gmail sudah digunakan
    check = (
        supabase.table("users")
        .select("id")
        .or_(f"username.eq.{username},gmail.eq.{gmail}")
        .limit(1)
        .execute()
    )
    if check.data:
        return RedirectResponse(
            "/register?error=exists",
            status_code=303
        )
    # Simpan user baru
    supabase.table("users").insert({
        "gmail": gmail,
        "username": username,
        "password": hash_password(password),
        "saldo": 0,
        "total_earn": 0,
        "referrals": 0,
        "is_banned": False
    }).execute()
    return RedirectResponse(
        url=f"/dashboard?login={username}",
        status_code=303
    )
# ======================================================
# DASHBOARD
# ======================================================
@app.get("/dashboard")
async def dashboard(
    request: Request,
    login: str | None = None
):
    if not login:
        return RedirectResponse(
            "/login",
            status_code=303
        )
    result = (
        supabase.table("users")
        .select("*")
        .or_(f"username.eq.{login},gmail.eq.{login}")
        .limit(1)
        .execute()
    )
    if not result.data:
        return RedirectResponse(
            "/login",
            status_code=303
        )
    user = result.data[0]
    if user.get("is_banned", False):
        return HTMLResponse(
            "Your account has been banned.",
            status_code=403
        )
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "username": user["username"]
        }
    )
# =========================
# CREATE LINK
# =========================
@app.post("/create-link")
async def create_link(request: Request):

    form = await request.form()
    login = form.get("login")
    destination_url = form.get("destination_url")

    user = supabase.table("users") \
        .select("id") \
        .eq("username", login) \
        .limit(1) \
        .execute()

    if not user.data:
        return RedirectResponse("/login", 303)

    user_id = user.data[0]["id"]

    short_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))

    supabase.table("links").insert({
        "user_id": user_id,
        "destination_url": destination_url,
        "short_code": short_code,
        "clicks": 0,
        "earnings": 0
    }).execute()

    return RedirectResponse(f"/dashboard?login={login}", 303)


# =========================
# SHORTLINK
# =========================
@app.get("/s/{short_code}")
async def shortlink(request: Request, short_code: str):

    res = (
        supabase.table("links")
        .select("*")
        .eq("short_code", short_code)
        .limit(1)
        .execute()
    )

    if not res.data:
        return HTMLResponse("Not found", 404)

    link = res.data[0]

    supabase.table("links").update({
        "clicks": (link.get("clicks") or 0) + 1
    }).eq("short_code", short_code).execute()

    token = secrets.token_urlsafe(32)

    supabase.table("download_tokens").insert({
        "token": token,
        "short_code": short_code,
        "step": 1,
        "used": False,
        "created_at": datetime.utcnow().isoformat()
    }).execute()

    return templates.TemplateResponse(
        "task1.html",
        {
            "request": request,
            "token": token,
            "destination_url": link["destination_url"]
        }
    )
# =========================
# TASK2
# =========================
@app.get("/task2/{token}")
async def task2(request: Request, token: str):

    token_data = (
        supabase.table("download_tokens")
        .select("*")
        .eq("token", token)
        .eq("step", 1)
        .eq("used", False)
        .limit(1)
        .execute()
    )

    if not token_data.data:
        return HTMLResponse("Access denied", 403)

    return templates.TemplateResponse(
        "task2.html",
        {
            "request": request,
            "token": token
        }
    )
# =========================
# COMPLETE TASK2
# =========================
@app.post("/complete-task2")
async def complete_task2(token: str = Form(...)):

    data = (
        supabase.table("download_tokens")
        .select("*")
        .eq("token", token)
        .eq("step", 1)
        .eq("used", False)
        .limit(1)
        .execute()
    )

    if not data.data:
        return HTMLResponse("Invalid Token", 403)

    supabase.table("download_tokens").update({
        "step": 2
    }).eq("token", token).execute()

    return RedirectResponse(
        f"/task3/{token}",
        303
    )
# =========================
# TASK3
# =========================
@app.get("/task3/{token}")
async def task3(request: Request, token: str):

    data = (
        supabase.table("download_tokens")
        .select("*")
        .eq("token", token)
        .eq("step", 2)
        .eq("used", False)
        .limit(1)
        .execute()
    )

    if not data.data:
        return HTMLResponse("Access denied", 403)

    return templates.TemplateResponse(
        "task3.html",
        {
            "request": request,
            "token": token
        }
    )
# =========================
# FINAL REWARD
# =========================
@app.post("/final-reward")
async def final_reward(token: str = Form(...)):

    token_res = (
        supabase.table("download_tokens")
        .select("*")
        .eq("token", token)
        .eq("step", 2)
        .eq("used", False)
        .limit(1)
        .execute()
    )

    if not token_res.data:
        return HTMLResponse("Invalid Token", 403)

    short_code = token_res.data[0]["short_code"]

    link = (
        supabase.table("links")
        .select("*")
        .eq("short_code", short_code)
        .limit(1)
        .execute()
    )

    if not link.data:
        return HTMLResponse("Link not found", 404)

    owner_id = link.data[0]["user_id"]

    owner = (
        supabase.table("users")
        .select("*")
        .eq("id", owner_id)
        .limit(1)
        .execute()
    )

    saldo = owner.data[0].get("saldo") or 0
    total = owner.data[0].get("total_earn") or 0

    reward = 300

    supabase.table("users").update({
        "saldo": saldo + reward,
        "total_earn": total + reward
    }).eq("id", owner_id).execute()

    supabase.table("download_tokens").update({
        "used": True
    }).eq("token", token).execute()

    return RedirectResponse("/", 303)

# =========================
# KELOLA TAUTAN
# =========================
@app.get("/links")
async def links(request: Request, login: str = None):

    if not login:
        return RedirectResponse("/login")

    user = (
        supabase.table("users")
        .select("id,username")
        .eq("username", login)
        .limit(1)
        .execute()
    )

    if not user.data:
        return RedirectResponse("/login")

    user_id = user.data[0]["id"]

    links = (
        supabase.table("links")
        .select("*")
        .eq("user_id", user_id)
        .order("id", desc=True)
        .execute()
    )

    return templates.TemplateResponse(
        "links.html",
        {
            "request": request,
            "username": login,
            "links": links.data
        }
    )
# =========================
# FAVICON
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
