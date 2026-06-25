import re
import random
import string

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
    return templates.TemplateResponse("index.html", {"request": request})


# =========================
# LOGIN
# =========================
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(login: str = Form(...), password: str = Form(...)):

    res = (
        supabase.table("users")
        .select("username, password")
        .or_(f"username.eq.{login},gmail.eq.{login}")
        .limit(1)
        .execute()
    )

    if not res.data:
        return RedirectResponse("/login?error=notfound", status_code=303)

    user = res.data[0]

    if not verify_password(password, user["password"]):
        return RedirectResponse("/login?error=wrongpass", status_code=303)

    return RedirectResponse(
        f"/dashboard?login={user['username']}",
        status_code=303
    )

@app.post("/forgot-password")
async def forgot_password(request: Request):
    form = await request.form()
    gmail = form.get("gmail")

    user = (
        supabase.table("users")
        .select("username, gmail")
        .eq("gmail", gmail)
        .limit(1)
        .execute()
    )

    if not user.data:
        return HTMLResponse("Email tidak ditemukan", status_code=404)

    user_data = user.data[0]

    token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

    # simpan token ke DB (WAJIB bikin kolom reset_token)
    supabase.table("users").update({
        "reset_token": token
    }).eq("gmail", gmail).execute()

    reset_link = f"https://yourdomain.com/reset-password?token={token}"

    # kirim email
    send_email(gmail, "Reset Password", f"Buka link ini: {reset_link}")

    return HTMLResponse("Cek email untuk reset password")

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_page(request: Request, token: str):

    return templates.TemplateResponse("reset.html", {
        "request": request,
        "token": token
    })

@app.post("/reset-password")
async def reset_password(request: Request):

    form = await request.form()
    token = form.get("token")
    new_password = form.get("password")

    user = (
        supabase.table("users")
        .select("username")
        .eq("reset_token", token)
        .limit(1)
        .execute()
    )

    if not user.data:
        return HTMLResponse("Token invalid", status_code=400)

    username = user.data[0]["username"]

    supabase.table("users").update({
        "password": hash_password(new_password),
        "reset_token": None
    }).eq("username", username).execute()

    return HTMLResponse("Password berhasil diganti")

# =========================
# REGISTER
# =========================
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_post(
    gmail: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):

    if password != confirm_password:
        return RedirectResponse("/register?error=nomatch", status_code=303)

    supabase.table("users").insert({
        "gmail": gmail,
        "username": username,
        "password": hash_password(password),
        "saldo": 0,
        "total_earn": 0,
        "referrals": 0
    }).execute()

    return RedirectResponse(f"/dashboard?login={username}", status_code=303)


# =========================
# DASHBOARD (FIXED created_link)
# =========================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, login: str = None):

    if not login:
        return RedirectResponse("/login")

    user_res = (
        supabase.table("users")
        .select("*")
        .or_(f"username.eq.{login},gmail.eq.{login}")
        .limit(1)
        .execute()
    )

    if not user_res.data:
        return RedirectResponse("/login")

    user = user_res.data[0]
    user_id = user["id"]

    # 🔥 FIX INI PENTING
    created_link = request.query_params.get("created", "")

    links = (
        supabase.table("links")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    ).data or []

    total_links = len(links)
    total_clicks = sum(int(l.get("clicks") or 0) for l in links)
    total_link_earnings = sum(int(l.get("earnings") or 0) for l in links)

    announcement = (
        supabase.table("announcements")
        .select("*")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    ).data

    announcement_text = announcement[0]["content"] if announcement else ""

    chat_messages = (
        supabase.table("chat_messages")
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

            "recent_links": links[:10],
            "announcement": announcement_text,
            "chat_messages": chat_messages,

            "created_link": created_link
        }
    )


# =========================
# CREATE LINK (FIXED REDIRECT)
# =========================
@app.post("/create-link")
async def create_link(request: Request):

    form = await request.form()

    login = form.get("login")
    destination_url = form.get("destination_url")

    user = (
        supabase.table("users")
        .select("id")
        .eq("username", login)
        .limit(1)
        .execute()
    )

    if not user.data:
        return RedirectResponse("/login", status_code=303)

    user_id = user.data[0]["id"]

    short_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))

    supabase.table("links").insert({
        "user_id": user_id,
        "destination_url": destination_url,
        "short_code": short_code,
        "clicks": 0,
        "earnings": 0
    }).execute()

    short_url = f"https://earnshortlink.up.railway.app/s/{short_code}"

    return RedirectResponse(
        f"/dashboard?login={login}&created={short_url}",
        status_code=303
    )


# =========================
# SHORTLINK (CLICK FIX)
# =========================
@app.get("/s/{short_code}", response_class=HTMLResponse)
async def shortlink(request: Request, short_code: str):

    res = (
        supabase.table("links")
        .select("*")
        .eq("short_code", short_code)
        .limit(1)
        .execute()
    )

    if not res.data:
        return HTMLResponse("Not found", status_code=404)

    link = res.data[0]

    supabase.table("links").update({
        "clicks": (link.get("clicks") or 0) + 1
    }).eq("short_code", short_code).execute()

    return templates.TemplateResponse(
        "task1.html",
        {
            "request": request,
            "short_code": short_code,
            "destination_url": link["destination_url"]
        }
    )


# =========================
# CHAT (FIXED)
# =========================
@app.post("/send-chat")
async def send_chat(request: Request):

    form = await request.form()

    login = form.get("login")
    message = form.get("message")

    if not login or not message:
        return RedirectResponse("/dashboard", status_code=303)

    supabase.table("chat_messages").insert({
        "username": login,
        "message": message
    }).execute()

    return RedirectResponse(f"/dashboard?login={login}", status_code=303)

# =========================
# ADMIN CHECK
# =========================
def is_admin(login: str):
    if not login:
        return False

    res = (
        supabase.table("users")
        .select("is_admin")
        .eq("username", login)
        .limit(1)
        .execute()
    )

    if not res.data:
        return False

    return bool(res.data[0].get("is_admin", False))


# =========================
# ADMIN PANEL
# =========================
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, login: str = None):

    if not is_admin(login):
        return HTMLResponse("403 Forbidden", status_code=403)

    users = supabase.table("users").select("*").execute().data or []
    links = supabase.table("links").select("*").execute().data or []
    chats = (
        supabase.table("chat_messages")
        .select("*")
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    ).data or []

    withdrawals = (
        supabase.table("withdrawals")
        .select("*")
        .order("created_at", desc=True)
        .execute()
    ).data or []

    total_earnings = sum(int(u.get("total_earn") or 0) for u in users)

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "login": login,

            "users": users,
            "links": links,
            "chats": chats,
            "withdrawals": withdrawals,

            "total_users": len(users),
            "total_links": len(links),
            "total_earnings": total_earnings
        }
    )

@app.post("/admin/wd/process")
async def wd_process(request: Request):
    form = await request.form()

    login = form.get("login")
    wd_id = form.get("id")

    if not is_admin(login):
        return HTMLResponse("Forbidden", status_code=403)

    supabase.table("withdrawals").update({
        "status": "process"
    }).eq("id", wd_id).execute()

    return RedirectResponse(f"/admin?login={login}", status_code=303)


@app.post("/admin/wd/success")
async def wd_success(request: Request):
    form = await request.form()

    login = form.get("login")
    wd_id = form.get("id")

    if not is_admin(login):
        return HTMLResponse("Forbidden", status_code=403)

    supabase.table("withdrawals").update({
        "status": "success"
    }).eq("id", wd_id).execute()

    return RedirectResponse(f"/admin?login={login}", status_code=303)


@app.post("/admin/wd/failed")
async def wd_failed(request: Request):
    form = await request.form()

    login = form.get("login")
    wd_id = form.get("id")

    if not is_admin(login):
        return HTMLResponse("Forbidden", status_code=403)

    supabase.table("withdrawals").update({
        "status": "failed"
    }).eq("id", wd_id).execute()

    return RedirectResponse(f"/admin?login={login}", status_code=303)

@app.post("/admin/ban")
async def ban_user(request: Request):
    form = await request.form()

    login = form.get("login")
    target = form.get("target")

    if not is_admin(login):
        return HTMLResponse("Forbidden", status_code=403)

    supabase.table("users").update({
        "is_banned": True
    }).eq("username", target).execute()

    return RedirectResponse(f"/admin?login={login}", status_code=303)


@app.post("/admin/unban")
async def unban_user(request: Request):
    form = await request.form()

    login = form.get("login")
    target = form.get("target")

    if not is_admin(login):
        return HTMLResponse("Forbidden", status_code=403)

    supabase.table("users").update({
        "is_banned": False
    }).eq("username", target).execute()

    return RedirectResponse(f"/admin?login={login}", status_code=303)


@app.post("/admin/reset-password")
async def reset_password(request: Request):

    form = await request.form()

    login = form.get("login")
    target = form.get("target")

    if not is_admin(login):
        return HTMLResponse("Forbidden", status_code=403)

    # generate password baru
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    supabase.table("users").update({
        "password": hash_password(new_password)
    }).eq("username", target).execute()

    return HTMLResponse(
        f"""
        <h3>Password baru untuk {target}:</h3>
        <h2>{new_password}</h2>
        <a href="/admin?login={login}">Kembali</a>
        """,
        status_code=200
    )
# =========================
# FAVICON
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
