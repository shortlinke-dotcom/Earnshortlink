import random
import string
import secrets
import os
from datetime import datetime

from fastapi import FastAPI, Request, Form, Body
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    Response,
    JSONResponse
)
from fastapi.templating import Jinja2Templates

from starlette.middleware.sessions import SessionMiddleware

from database import supabase
from auth import hash_password, verify_password


app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key="RAHASIA_PANJANG_123"
)

templates = Jinja2Templates(directory="templates")

SUPABASE_URL = os.getenv("SUPABASE_URL")


# =========================
# HOME
# =========================
@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# =========================
# LOGIN PAGE
# =========================
@app.get("/login")
async def login_page(request: Request, error: str | None = None):

    message = None

    if error == "notfound":
        message = "❌ Username atau Gmail tidak ditemukan."
    elif error == "wrongpass":
        message = "❌ Password salah."
    elif error == "banned":
        message = "🚫 Akun diblokir."

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": message}
    )


# =========================
# LOGIN
# =========================
@app.post("/login")
async def login_post(request: Request, login: str = Form(...), password: str = Form(...)):

    result = (
        supabase.table("users")
        .select("*")
        .eq("gmail", login)
        .limit(1)
        .execute()
    )

    if not result.data:
        return RedirectResponse("/login?error=notfound", 303)

    user = result.data[0]

    if user.get("is_banned"):
        return RedirectResponse("/login?error=banned", 303)

    if not verify_password(password, user.get("password", "")):
        return RedirectResponse("/login?error=wrongpass", 303)

    request.session["username"] = user["username"]

    return RedirectResponse("/dashboard", 303)


# =========================
# GOOGLE LOGIN
# =========================
@app.get("/auth/google")
async def auth_google():
    url = (
        f"{SUPABASE_URL}/auth/v1/authorize"
        f"?provider=google"
        f"&redirect_to=https://eslink.up.railway.app/auth/callback"
    )
    return RedirectResponse(url)


@app.post("/auth/google-session")
async def google_session(request: Request, data: dict = Body(...)):

    access_token = data.get("access_token")

    if not access_token:
        return JSONResponse({"redirect": "/login?error=google_failed"})

    try:
        user_data = supabase.auth.get_user(access_token)
        email = user_data.user.email if user_data and user_data.user else None
    except:
        return JSONResponse({"redirect": "/login?error=google_failed"})

    if not email:
        return JSONResponse({"redirect": "/login?error=google_failed"})

    result = (
        supabase.table("users")
        .select("*")
        .eq("gmail", email)
        .limit(1)
        .execute()
    )

    if not result.data:
        request.session["pending_email"] = email
        return JSONResponse({"redirect": "/setup-username"})

    user = result.data[0]

    if user.get("is_banned"):
        return JSONResponse({"redirect": "/login?error=banned"})

    request.session["username"] = user["username"]

    return JSONResponse({"redirect": "/dashboard"})

from fastapi import Request
from fastapi.responses import RedirectResponse

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str | None = None, error: str | None = None):

    if error:
        return RedirectResponse("/login?error=google_failed")

    if not code:
        return RedirectResponse("/login?error=google_failed")

    try:
        # tukar code jadi session dari supabase
        session = supabase.auth.exchange_code_for_session(code)

        user = session.user
        email = user.email

    except Exception as e:
        print("OAuth callback error:", e)
        return RedirectResponse("/login?error=google_failed")

    # cek user di database kamu
    result = (
        supabase.table("users")
        .select("*")
        .eq("gmail", email)
        .limit(1)
        .execute()
    )

    # kalau belum ada → setup username
    if not result.data:
        request.session["pending_email"] = email
        return RedirectResponse("/setup-username")

    db_user = result.data[0]

    # banned check
    if db_user.get("is_banned"):
        return RedirectResponse("/login?error=banned")

    # login session
    request.session["username"] = db_user["username"]

    return RedirectResponse("/dashboard")
    
# =========================
# SETUP USERNAME
# =========================
@app.get("/setup-username")
async def setup_username(request: Request):

    email = request.session.get("pending_email")

    if not email:
        return RedirectResponse("/login", 303)

    return templates.TemplateResponse(
        "setup_username.html",
        {"request": request, "email": email}
    )


@app.post("/setup-username")
async def setup_username_post(request: Request, username: str = Form(...)):

    email = request.session.get("pending_email")

    if not email:
        return RedirectResponse("/login", 303)

    username = username.strip().lower()

    if len(username) < 3:
        return RedirectResponse("/setup-username?error=short", 303)

    if " " in username:
        return RedirectResponse("/setup-username?error=space", 303)

    check = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if check.data:
        return RedirectResponse("/setup-username?error=exists", 303)

    supabase.table("users").insert({
        "gmail": email,
        "username": username,
        "password": "",
        "saldo": 0,
        "total_earn": 0,
        "referrals": 0,
        "is_banned": False
    }).execute()

    request.session["username"] = username
    request.session.pop("pending_email", None)

    return RedirectResponse("/dashboard", 303)


# =========================
# REGISTER
# =========================
@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register_post(
    request: Request,
    gmail: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):

    gmail = gmail.strip().lower()
    username = username.strip().lower()

    if password != confirm_password:
        return RedirectResponse("/register?error=nomatch", 303)

    check = (
        supabase.table("users")
        .select("id")
        .or_(f"username.eq.{username},gmail.eq.{gmail}")
        .limit(1)
        .execute()
    )

    if check.data:
        return RedirectResponse("/register?error=exists", 303)

    supabase.table("users").insert({
        "gmail": gmail,
        "username": username,
        "password": hash_password(password),
        "saldo": 0,
        "total_earn": 0,
        "referrals": 0,
        "is_banned": False
    }).execute()

    request.session["username"] = username

    return RedirectResponse("/dashboard", 303)


# =========================
# DASHBOARD
# =========================
@app.get("/dashboard")
async def dashboard(request: Request):

    username = request.session.get("username")

    if not username:
        return RedirectResponse("/login", status_code=303)

    result = (
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if not result.data:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    user = result.data[0]

    if user.get("is_banned"):
        request.session.clear()
        return RedirectResponse("/login?error=banned", status_code=303)

    links_res = (
        supabase.table("links")
        .select("*")
        .eq("user_id", user["id"])
        .order("id", desc=True)
        .execute()
    )

    links = links_res.data or []

    total_links = len(links)
    total_clicks = sum(link["clicks"] for link in links)
    total_earnings = sum(link["earnings"] for link in links)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,

            "user": user,

            "username": user["username"],
            "saldo": user["saldo"],

            "total_links": total_links,
            "total_clicks": total_clicks,
            "today_earnings": total_earnings,

            "latest_links": links[:5],

            "referral_code": user["username"],

            "links": links
        }
    )
# =========================
# CREATE LINK
# =========================
from fastapi.responses import JSONResponse

@app.post("/create-link")
async def create_link(request: Request, destination_url: str = Form(...)):

    username = request.session.get("username")

    if not username:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    user = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if not user.data:
        return JSONResponse({"ok": False, "error": "user_not_found"}, status_code=404)

    user_id = user.data[0]["id"]

    if not destination_url.startswith(("http://", "https://")):
        return JSONResponse({"ok": False, "error": "invalid_url"}, status_code=400)

    while True:
        short_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))

        check = (
            supabase.table("links")
            .select("id")
            .eq("short_code", short_code)
            .limit(1)
            .execute()
        )

        if not check.data:
            break

    supabase.table("links").insert({
        "user_id": user_id,
        "destination_url": destination_url,
        "short_code": short_code,
        "clicks": 0,
        "earnings": 0
    }).execute()

    short_link = f"{request.base_url}s/{short_code}"

    return JSONResponse({
        "ok": True,
        "short_link": short_link,
        "short_code": short_code
    })

# =========================
# SHORTLINK
# =========================
@app.get("/s/{short_code}")
async def shortlink(request: Request, short_code: str):

    # 1. ambil link
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

    # 2. update klik (aman dari null)
    try:
        supabase.table("links").update({
            "clicks": (link.get("clicks") or 0) + 1
        }).eq("short_code", short_code).execute()
    except Exception as e:
        print("Click update error:", e)

    # 3. generate token
    token = secrets.token_urlsafe(32)

    # 4. insert download token (SAFE MODE)
    try:
        supabase.table("download_tokens").insert({
            "token": token,
            "short_code": short_code,
            "step": 1,
            "used": False,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
    except Exception as e:
        print("Token insert error:", e)
        return HTMLResponse("Server error", 500)

    # 5. render task
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

    if not request.session.get("username"):
        return HTMLResponse("Unauthorized", 401)

    return templates.TemplateResponse(
        "task2.html",
        {"request": request, "token": token}
    )


# =========================
# COMPLETE TASK2
# =========================
@app.post("/complete-task2")
async def complete_task2(request: Request, token: str = Form(...)):

    if not request.session.get("username"):
        return HTMLResponse("Unauthorized", 401)

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

    return RedirectResponse(f"/task3/{token}", 303)


# =========================
# TASK3
# =========================
@app.get("/task3/{token}")
async def task3(request: Request, token: str):

    if not request.session.get("username"):
        return HTMLResponse("Unauthorized", 401)

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
        {"request": request, "token": token}
    )


# =========================
# FINAL REWARD
# =========================
@app.post("/final-reward")
async def final_reward(request: Request, token: str = Form(...)):

    if not request.session.get("username"):
        return HTMLResponse("Unauthorized", 401)

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

    owner_id = link.data[0]["user_id"]

    owner = (
        supabase.table("users")
        .select("saldo,total_earn")
        .eq("id", owner_id)
        .limit(1)
        .execute()
    )

    reward = 300

    saldo = owner.data[0]["saldo"] or 0
    total = owner.data[0]["total_earn"] or 0

    supabase.table("users").update({
        "saldo": saldo + reward,
        "total_earn": total + reward
    }).eq("id", owner_id).execute()

    supabase.table("download_tokens").update({
        "used": True
    }).eq("token", token).execute()

    return RedirectResponse("/", 303)


# =========================
# LINKS
# =========================
@app.get("/links")
async def links(request: Request):

    username = request.session.get("username")

    if not username:
        return RedirectResponse("/login", 303)

    user = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    user_id = user.data[0]["id"]

    links_res = (
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
            "username": username,
            "links": links_res.data or []
        }
    )


# =========================
# LOGOUT
# =========================
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)


# =========================
# FAVICON
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
