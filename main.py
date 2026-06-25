import re
import random
import string
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
    return templates.TemplateResponse("index.html", {"request": request})


# =========================
# LOGIN
# =========================
@app.post("/login")
def login_post(login: str = Form(...), password: str = Form(...)):

    result = (
        supabase.table("users")
        .select("username, password")
        .or_(f"username.eq.{login},gmail.eq.{login}")
        .limit(1)
        .execute()
    )

    if not result.data:
        return RedirectResponse("/login?error=notfound", status_code=303)

    user = result.data[0]

    if not verify_password(password, user["password"]):
        return RedirectResponse("/login?error=wrongpass", status_code=303)

    return RedirectResponse(
        f"/dashboard?login={user['username']}",
        status_code=303
    )


# =========================
# REGISTER
# =========================
@app.post("/register")
def register_post(gmail: str = Form(...),
                  username: str = Form(...),
                  password: str = Form(...),
                  confirm_password: str = Form(...)):

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
# DASHBOARD
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

    created_link = request.query_params.get("created")

    links_res = (
        supabase.table("links")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )

    links = links_res.data or []

    total_links = len(links)
    total_clicks = sum(int(l.get("clicks") or 0) for l in links)
    total_link_earnings = sum(int(l.get("earnings") or 0) for l in links)

    recent_links = links[:10]

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

            "recent_links": recent_links,
            "announcement": announcement_text,
            "chat_messages": chat_messages,

            # ✅ FIX INI PENTING
            "created_link": created_link
        }
    )


# =========================
# CREATE LINK (FIXED)
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

    short_code = ''.join(
        random.choices(string.ascii_letters + string.digits, k=6)
    )

    supabase.table("links").insert({
        "user_id": user_id,
        "destination_url": destination_url,
        "short_code": short_code,
        "clicks": 0,
        "earnings": 0
    }).execute()

    short_url = f"/s/{short_code}"

    return RedirectResponse(
        f"/dashboard?login={login}&created={short_url}",
        status_code=303
    )


# =========================
# SHORTLINK
# =========================
@app.get("/s/{short_code}", response_class=HTMLResponse)
async def shortlink(request: Request, short_code: str):

    result = (
        supabase.table("links")
        .select("*")
        .eq("short_code", short_code)
        .limit(1)
        .execute()
    )

    if not result.data:
        return HTMLResponse("Not found", status_code=404)

    link = result.data[0]

    # 🔥 increment click
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
# CHAT
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


# ========================
#ADMIN PANEL
# ========================
def is_admin(login: str):
    res = (
        supabase.table("users")
        .select("is_admin")
        .eq("username", login)
        .limit(1)
        .execute()
    )

    if not res.data:
        return False

    return bool(res.data[0].get("is_admin"))

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, login: str = None):

    if not login or not is_admin(login):
        return HTMLResponse("403 Forbidden", status_code=403)

    users = supabase.table("users").select("*").execute().data or []
    links = supabase.table("links").select("*").execute().data or []
    chats = supabase.table("chat_messages").select("*").order("created_at", desc=True).limit(50).execute().data or []

    total_users = len(users)
    total_links = len(links)
    total_earnings = sum(int(u.get("total_earn") or 0) for u in users)

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "login": login,

            "users": users,
            "links": links,
            "chats": chats,

            "total_users": total_users,
            "total_links": total_links,
            "total_earnings": total_earnings
        }
    )

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

@app.post("/admin/broadcast")
async def broadcast(request: Request):

    form = await request.form()
    login = form.get("login")
    message = form.get("message")

    if not is_admin(login):
        return HTMLResponse("Forbidden", status_code=403)

    supabase.table("announcements").insert({
        "title": "Broadcast",
        "content": message
    }).execute()

    return RedirectResponse(f"/admin?login={login}", status_code=303)
# =========================
# FAVICON
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
