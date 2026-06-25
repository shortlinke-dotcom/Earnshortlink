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

    try:
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
        user_id = int(user["id"])

        # =========================
        # USER LINKS
        # =========================

        links = []

        try:
            links_res = (
                supabase
                .table("links")
                .select("*")
                .eq("user_id", user_id)
                .execute()
            )

            links = links_res.data or []

        except Exception as e:
            print("LINKS ERROR:", e)

        total_links = len(links)

        total_clicks = sum(
            int(link.get("clicks") or 0)
            for link in links
        )

        total_link_earnings = sum(
            int(link.get("earnings") or 0)
            for link in links
        )

        # =========================
        # RECENT LINKS
        # =========================

        recent_links = []

        try:
            recent_links = (
                supabase
                .table("links")
                .select("*")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .limit(10)
                .execute()
            ).data or []

        except Exception as e:
            print("RECENT LINKS ERROR:", e)

        # =========================
        # ANNOUNCEMENT
        # =========================

        announcement_text = ""

        try:
            announcement = (
                supabase
                .table("announcements")
                .select("*")
                .order("created_at", desc=True)
                .limit(1)
                .execute()
            ).data

            if announcement:
                announcement_text = announcement[0].get("content", "")

        except Exception as e:
            print("ANNOUNCEMENT ERROR:", e)

        # =========================
        # CHAT
        # =========================

        chat_messages = []

        try:
            chat_messages = (
                supabase
                .table("chat_messages")
                .select("*")
                .order("created_at", desc=True)
                .limit(30)
                .execute()
            ).data or []

        except Exception as e:
            print("CHAT ERROR:", e)

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,

                "username": user.get("username", "User"),

                "saldo": int(user.get("saldo") or 0),

                "total_earn": int(user.get("total_earn") or 0),

                "referrals": int(user.get("referrals") or 0),

                "total_links": total_links,

                "total_clicks": total_clicks,

                "total_link_earnings": total_link_earnings,

                "announcement": announcement_text,

                "recent_links": recent_links,

                "chat_messages": chat_messages
            }
        )

    except Exception as e:
        print("DASHBOARD ERROR:", e)
        return HTMLResponse(
            f"<h1>Dashboard Error</h1><pre>{e}</pre>",
            status_code=500
        )
# =========================
# SEND CHAT
# =========================
@app.post("/send-chat")
async def send_chat(
    login: str = Form(...),
    message: str = Form(...)
):

    if not message.strip():
        return RedirectResponse(
            f"/dashboard?login={login}",
            status_code=303
        )

    supabase.table("chat_messages").insert({
        "username": login,
        "message": message.strip()
    }).execute()

    return RedirectResponse(
        f"/dashboard?login={login}",
        status_code=303
    )
# =========================
# FAVICON (IGNORE ERROR LOG)
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
