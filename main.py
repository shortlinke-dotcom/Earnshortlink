import random
import string
import secrets
from datetime import datetime

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
@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# =========================
# LOGIN
# =========================
@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_post(login: str = Form(...), password: str = Form(...)):

    res = supabase.table("users") \
        .select("username,password,is_banned") \
        .or_(f"username.eq.{login},gmail.eq.{login}") \
        .limit(1) \
        .execute()

    if not res.data:
        return RedirectResponse("/login?error=notfound", 303)

    user = res.data[0]

    if user.get("is_banned"):
        return RedirectResponse("/login?error=banned", 303)

    if not verify_password(password, user["password"]):
        return RedirectResponse("/login?error=wrongpass", 303)

    return RedirectResponse(f"/dashboard?login={user['username']}", 303)


# =========================
# REGISTER
# =========================
@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register_post(
    gmail: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):

    if password != confirm_password:
        return RedirectResponse("/register?error=nomatch", 303)

    supabase.table("users").insert({
        "gmail": gmail,
        "username": username,
        "password": hash_password(password),
        "saldo": 0,
        "total_earn": 0,
        "referrals": 0,
        "is_banned": False
    }).execute()

    return RedirectResponse(f"/dashboard?login={username}", 303)


# =========================
# DASHBOARD
# =========================
@app.get("/dashboard")
async def dashboard(request: Request, login: str = None):

    if not login:
        return RedirectResponse("/login")

    user_res = supabase.table("users") \
        .select("*") \
        .or_(f"username.eq.{login},gmail.eq.{login}") \
        .limit(1) \
        .execute()

    if not user_res.data:
        return RedirectResponse("/login")

    user = user_res.data[0]

    if user.get("is_banned"):
        return HTMLResponse("Banned", status_code=403)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user
    })


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
# SHORTLINK -> TASK FLOW START
# =========================
@app.get("/s/{short_code}")
async def shortlink(request: Request, short_code: str):

    res = supabase.table("links") \
        .select("*") \
        .eq("short_code", short_code) \
        .limit(1) \
        .execute()

    if not res.data:
        return HTMLResponse("Not found", 404)

    link = res.data[0]

    supabase.table("links").update({
        "clicks": (link.get("clicks") or 0) + 1
    }).eq("short_code", short_code).execute()

    token = secrets.token_urlsafe(24)

    supabase.table("download_tokens").insert({
        "token": token,
        "short_code": short_code,
        "step": 1,
        "used": False
    }).execute()

    return templates.TemplateResponse("task1.html", {
        "request": request,
        "token": token,
        "destination_url": link["destination_url"]
    })


# =========================
# TASK 2 (LOCKED)
# =========================
@app.get("/task2/{token}")
async def task2(request: Request, token: str):

    data = supabase.table("download_tokens") \
        .select("*") \
        .eq("token", token) \
        .eq("step", 1) \
        .eq("used", False) \
        .limit(1) \
        .execute()

    if not data.data:
        return HTMLResponse("Invalid access", 403)

    return templates.TemplateResponse("task2.html", {
        "request": request,
        "token": token
    })


# =========================
# TASK 2 COMPLETE
# =========================
@app.post("/complete-task2")
async def complete_task2(request: Request):

    form = await request.form()
    token = form.get("token")

    supabase.table("download_tokens") \
        .update({"step": 2}) \
        .eq("token", token) \
        .execute()

    return RedirectResponse(f"/task3/{token}", 303)


# =========================
# TASK 3 (FINAL STEP)
# =========================
@app.get("/task3/{token}")
async def task3(request: Request, token: str):

    data = supabase.table("download_tokens") \
        .select("*") \
        .eq("token", token) \
        .eq("step", 2) \
        .eq("used", False) \
        .limit(1) \
        .execute()

    if not data.data:
        return HTMLResponse("Invalid access", 403)

    return templates.TemplateResponse("task3.html", {
        "request": request,
        "token": token
    })


# =========================
# FINAL REWARD (FIXED REAL OWNER PAYMENT)
# =========================
@app.post("/final-reward")
async def final_reward(request: Request):

    form = await request.form()
    token = (form.get("token") or "").strip()

    if not token:
        return RedirectResponse("/dashboard", status_code=303)

    # 1. VALIDASI TOKEN
    token_res = supabase.table("download_tokens") \
        .select("short_code, used, step") \
        .eq("token", token) \
        .eq("step", 2) \
        .eq("used", False) \
        .limit(1) \
        .execute()

    if not token_res.data:
        return RedirectResponse("/dashboard", status_code=303)

    short_code = token_res.data[0]["short_code"]

    # 2. AMBIL OWNER LINK
    link_res = supabase.table("links") \
        .select("user_id") \
        .eq("short_code", short_code) \
        .limit(1) \
        .execute()

    if not link_res.data:
        return RedirectResponse("/dashboard", status_code=303)

    user_id = link_res.data[0]["user_id"]

    # 3. AMBIL SALDO CURRENT
    user_res = supabase.table("users") \
        .select("saldo") \
        .eq("id", user_id) \
        .limit(1) \
        .execute()

    if not user_res.data:
        return RedirectResponse("/dashboard", status_code=303)

    current_saldo = user_res.data[0].get("saldo") or 0

    # 4. UPDATE SALDO OWNER LINK
    supabase.table("users") \
        .update({
            "saldo": current_saldo + 300
        }) \
        .eq("id", user_id) \
        .execute()

    # 5. LOCK TOKEN (ANTI DOUBLE CLAIM)
    supabase.table("download_tokens") \
        .update({
            "used": True
        }) \
        .eq("token", token) \
        .execute()

    return RedirectResponse("/dashboard", status_code=303)
# =========================
# CHECK ACCESS API
# =========================
@app.get("/api/check-access")
async def check_access(token: str):

    res = supabase.table("download_tokens") \
        .select("*") \
        .eq("token", token) \
        .eq("used", False) \
        .limit(1) \
        .execute()

    return {"valid": bool(res.data)}


# =========================
# FAVICON
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
