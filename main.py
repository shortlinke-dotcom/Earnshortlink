import os
import random
import string
import secrets
import calendar
import bcrypt
import traceback
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request, Form, Body
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response
)
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

from auth import hash_password, verify_password
from database import supabase


# =========================
# APP INIT (ONLY ONCE)
# =========================

app = FastAPI()
oauth = OAuth()

oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
    authorize_params={"prompt": "select_account"}
)
# Ambil secret dari Railway Environment Variables
SESSION_SECRET = os.getenv(
    "SESSION_SECRET",
    "Yeni-saputra-keynarra-14072025"
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True,
)

print("SESSION_SECRET:", SESSION_SECRET)
print("MIDDLEWARE:", app.user_middleware)

templates = Jinja2Templates(directory="templates")

SUPABASE_URL = os.getenv("SUPABASE_URL")

@app.middleware("http")
async def check_session(request: Request, call_next):

    path = request.url.path

    public_paths = {
        "/",
        "/login",
        "/register",
        "/auth/google",
        "/auth/callback",
        "/setup-username",
        "/check-username",
        "/privacy",
        "/terms",
        "/favicon.ico"
    }

    # =========================
    # SKIP AUTH FOR PUBLIC ROUTES
    # =========================
    if (
        path in public_paths
        or path.startswith("/s/")
        or path.startswith("/pay/")
        or path.startswith("/ref/")
        or path.startswith("/task")
    ):
        return await call_next(request)

    # =========================
    # GET TOKEN
    # =========================
    token = request.cookies.get("session_token")

    if not token:
        return RedirectResponse("/login", status_code=303)

    # =========================
    # VALIDATE USER
    # =========================
    try:
        res = (
            supabase.table("users")
            .select("id, username, last_activity")
            .eq("session_token", token)
            .limit(1)
            .execute()
        )
    except Exception as e:
        print("DB ERROR:", e)
        return RedirectResponse("/login", status_code=303)

    if not res.data:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("session_token")
        return response

    user = res.data[0]

    # =========================
    # OPTIONAL EXPIRY CHECK (SAFE)
    # =========================
    try:
        if user.get("last_activity"):
            last = datetime.fromisoformat(
                user["last_activity"].replace("Z", "+00:00")
            )

            if datetime.now(timezone.utc) - last > timedelta(hours=24):
                supabase.table("users").update({
                    "session_token": None
                }).eq("id", user["id"]).execute()

                response = RedirectResponse("/login", status_code=303)
                response.delete_cookie("session_token")
                return response

    except Exception as e:
        print("TIME PARSE ERROR:", e)

    # =========================
    # SET SESSION (SAFE ONLY)
    # =========================
    if "session" in request.scope:
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["logged_in"] = True

    # ⚠️ UPDATE last_activity ONLY IF NEEDED (anti spam DB)
    request.state.user = user  # optional for route usage

    return await call_next(request)

@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    error_text = traceback.format_exc()

    return HTMLResponse(f"""
    <html>
    <head>
        <title>Server Error</title>
        <style>
            body {{
                background:#0f172a;
                color:#fff;
                font-family:monospace;
                padding:20px;
            }}
            pre {{
                background:#111827;
                padding:15px;
                border-radius:10px;
                overflow:auto;
            }}
        </style>
    </head>
    <body>
        <h2>🚨 Internal Server Error</h2>
        <p>Detail error:</p>
        <pre>{error_text}</pre>
    </body>
    </html>
    """, status_code=500)
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
async def login_post(
    request: Request,
    login: str = Form(...),
    password: str = Form(...)
):
    result = (
        supabase.table("users")
        .select("*")
        .or_(f"gmail.eq.{login},username.eq.{login.lower()}")
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
    request.session["user_id"] = user["id"]
    request.session["logged_in"] = True

    token = secrets.token_hex(32)

    supabase.table("users").update({
        "session_token": token,
        "last_activity": datetime.now(timezone.utc).isoformat()
    }).eq("id", user["id"]).execute()

    request.session["session_token"] = token

    response = RedirectResponse("/dashboard", 303)

    response.set_cookie(
        key="session_token",
        value=token,
        max_age=2592000,
        httponly=True,
        samesite="lax",
        secure=True
    )

    return response


# =========================
# GOOGLE LOGIN (START)
# =========================
@app.get("/auth/google")
async def auth_google(request: Request):
    redirect_uri = "https://eslink.up.railway.app/auth/callback"
    return await oauth.google.authorize_redirect(
        request,
        redirect_uri
    )
    
# =========================
# GOOGLE CALLBACK (FINAL)
# =========================

@app.get("/auth/callback")
async def auth_callback(request: Request):
    print("=== GOOGLE CALLBACK HIT ===")
    print("SESSION BEFORE:", dict(request.session))
    print("COOKIES:", request.cookies)

    try:
        token = await oauth.google.authorize_access_token(request)
        print("TOKEN:", token)

    except Exception as e:
        print("TOKEN ERROR:", str(e))
        traceback.print_exc()
        return RedirectResponse("/oauth-error", status_code=303)

    user = token.get("userinfo")
    print("USERINFO:", user)

    if not user:
        return HTMLResponse("Google login gagal (no userinfo)", 400)

    email = user["email"].lower().strip()
    print("EMAIL:", email)

    try:
        result = (
            supabase.table("users")
            .select("*")
            .eq("gmail", email)
            .limit(1)
            .execute()
        )

        print("DB RESULT:", result.data)

    except Exception as e:
        print("DB ERROR:", str(e))
        traceback.print_exc()
        return HTMLResponse("DB error", 500)

    if not result.data:
        request.session["pending_email"] = email
        print("NEW USER FLOW")
        return RedirectResponse("/setup-username", status_code=303)

    db_user = result.data[0]

    request.session["user_id"] = db_user["id"]
    request.session["username"] = db_user["username"]
    request.session["logged_in"] = True

    token_session = secrets.token_hex(32)

    supabase.table("users").update({
        "session_token": token_session,
        "last_activity": datetime.now(timezone.utc).isoformat()
    }).eq("id", db_user["id"]).execute()

    response = RedirectResponse("/dashboard", status_code=303)

    response.set_cookie(
        key="session_token",
        value=token_session,
        max_age=2592000,
        httponly=True,
        samesite="lax",
        secure=True
    )

    return response
    
# =========================
# SETUP USERNAME (GET)
# =========================
@app.get("/setup-username")
async def setup_username(request: Request):

    # kalau sudah login langsung dashboard
    if request.session.get("logged_in"):
        return RedirectResponse("/dashboard", 303)

    email = request.session.get("pending_email")

    # tidak ada email pending
    if not email:
        return RedirectResponse("/login", 303)

    # pengaman: kalau email ternyata sudah terdaftar
    user = (
        supabase.table("users")
        .select("id")
        .eq("gmail", email)
        .limit(1)
        .execute()
    )

    if user.data:
        request.session.pop("pending_email", None)
        return RedirectResponse("/login", 303)

    return templates.TemplateResponse(
        "setup_username.html",
        {
            "request": request,
            "email": email
        }
    )

# =========================
# SETUP USERNAME (POST)
# =========================

@app.post("/setup-username")
async def setup_username_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    email = request.session.get("pending_email")

    if not email:
        return JSONResponse(
            {"ok": False, "error": "session_expired"},
            status_code=401
        )

    username = username.strip().lower()
    password = password.strip()

    # VALIDASI USERNAME
    if len(username) < 3:
        return JSONResponse({"ok": False, "error": "username_too_short"})

    if " " in username:
        return JSONResponse({"ok": False, "error": "username_no_space"})

    # VALIDASI PASSWORD
    if len(password) < 6:
        return JSONResponse({"ok": False, "error": "password_too_short"})

    if len(password) > 72:
        return JSONResponse({"ok": False, "error": "password_too_long"})

    # EMAIL SUDAH TERDAFTAR → LANGSUNG LOGIN
    existing_email = (
        supabase.table("users")
        .select("id,username")
        .eq("gmail", email)
        .limit(1)
        .execute()
    )

    if existing_email.data:
        user = existing_email.data[0]

        request.session["username"] = user["username"]
        request.session["user_id"] = user["id"]
        request.session["logged_in"] = True

        token = secrets.token_hex(32)

        supabase.table("users").update({
            "session_token": token,
            "last_activity": datetime.now(timezone.utc).isoformat()
        }).eq("id", user["id"]).execute()

        request.session["session_token"] = token
        request.session.pop("pending_email", None)

        response = JSONResponse({
            "ok": True,
            "redirect": "/dashboard"
        })

        response.set_cookie(
            key="session_token",
            value=token,
            max_age=2592000,
            httponly=True,
            samesite="lax",
            secure=True
        )

        return response

    # CEK USERNAME
    check = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if check.data:
        return JSONResponse({
            "ok": False,
            "error": "username_exists"
        })

    # HASH PASSWORD
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # INSERT USER
    insert = (
        supabase.table("users")
        .insert({
            "gmail": email,
            "username": username,
            "password": hashed_password,
        })
        .execute()
    )

    print("INSERT RESULT:", insert)
    print("INSERT DATA:", insert.data)

    if not insert.data:
        print("INSERT FAILED")
        return JSONResponse({
            "ok": False,
            "error": "insert_failed"
        })

    new_user = insert.data[0]
    print("NEW USER:", new_user)

    request.session["username"] = new_user["username"]
    request.session["user_id"] = new_user["id"]
    request.session["logged_in"] = True

    token = secrets.token_hex(32)

    supabase.table("users").update({
        "session_token": token,
        "last_activity": datetime.now(timezone.utc).isoformat()
    }).eq("id", new_user["id"]).execute()

    request.session["session_token"] = token
    request.session.pop("pending_email", None)

    response = JSONResponse({
        "ok": True,
        "redirect": "/dashboard"
    })

    response.set_cookie(
        key="session_token",
        value=token,
        max_age=2592000,
        httponly=True,
        samesite="lax",
        secure=True
    )

    return response


# =========================
# REFERRAL LINK
# =========================
@app.get("/ref/{username}")
async def referral(request: Request, username: str):

    user = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if not user.data:
        return HTMLResponse("Referral tidak ditemukan", 404)

    request.session["referral"] = username

    return RedirectResponse("/register", status_code=303)


# =========================
# REGISTER PAGE
# =========================
@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


# =========================
# REGISTER POST
# =========================
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

    # =========================
    # VALIDASI
    # =========================
    if password != confirm_password:
        return RedirectResponse("/register?error=nomatch", 303)

    if len(username) < 3:
        return RedirectResponse("/register?error=short", 303)

    if " " in username:
        return RedirectResponse("/register?error=space", 303)

    # =========================
    # CEK USER EXIST
    # =========================
    check = (
        supabase.table("users")
        .select("id")
        .or_(f"username.eq.{username},gmail.eq.{gmail}")
        .limit(1)
        .execute()
    )

    if check.data:
        return RedirectResponse("/register?error=exists", 303)

    # =========================
    # INSERT USER (AMBIL DATA LANGSUNG)
    # =========================
    insert = (
        supabase.table("users")
        .insert({
            "gmail": gmail,
            "username": username,
            "password": hash_password(password),
        })
        .execute()
    )

    if not insert.data:
        return RedirectResponse("/register?error=failed", 303)

    new_user = insert.data[0]
    new_user_id = new_user.get("id")

    # =========================
    # REFERRAL SYSTEM
    # =========================
    referral = request.session.get("referral")

    if referral:
        ref = (
            supabase.table("users")
            .select("id,total_referral,referral_earnings")
            .eq("username", referral)
            .limit(1)
            .execute()
        )

        if ref.data:
            referrer = ref.data[0]
            referrer_id = referrer["id"]

            # simpan relasi
            supabase.table("referrals").insert({
                "user_id": referrer_id,
                "referred_user_id": new_user_id,
                "referral_paid": False
            }).execute()

            # update statistik referral
            supabase.table("users").update({
                "total_referral": (referrer.get("total_referral") or 0) + 1,
                "referral_earnings": (referrer.get("referral_earnings") or 0) + 500
            }).eq("id", referrer_id).execute()

        # hapus session referral
        request.session.pop("referral", None)

    # =========================
    # AUTO LOGIN
    # =========================
    request.session["username"] = username
    request.session["user_id"] = new_user_id
    request.session["logged_in"] = True

    return RedirectResponse("/dashboard", status_code=303)

@app.get("/check-username")
async def check_username(request: Request, u: str = ""):
    try:
        username = u.strip().lower()

        if len(username) < 3:
            return JSONResponse({
                "exists": False,
                "valid": False,
                "message": "Minimal 3 karakter"
            })

        user = (
            supabase.table("users")
            .select("id")
            .eq("username", username)
            .limit(1)
            .execute()
        )

        return JSONResponse({
            "exists": bool(user.data),
            "valid": True
        })

    except Exception as e:
        print("CHECK USERNAME ERROR:", e)
        return JSONResponse(
            {
                "exists": False,
                "valid": False,
                "message": "Server error"
            },
            status_code=500
        )

# =========================
# DASHBOARD
# =========================

@app.get("/dashboard")
async def dashboard(request: Request):

    # ================= SESSION =================
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=303)

    # ================= PENGUMUMAN =================
    announcement = None
    unread_count = 0

    try:
        res = (
            supabase.table("announcements")
            .select("*")
            .eq("active", True)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )

        if res.data:
            announcement = res.data[0]

    except Exception as e:
        print("Announcement error:", e)

    # ================= USER =================
    user_res = (
        supabase.table("users")
        .select("*")
        .eq("id", user_id)
        .limit(1)
        .execute()
    )

    user = (user_res.data or [None])[0]

    if not user:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    if user.get("is_banned"):
        request.session.clear()
        return RedirectResponse(
            "/login?error=banned",
            status_code=303
        )

    # lanjutkan kode dashboard yang sudah ada...

    # ================= LINKS =================
    links_res = (
        supabase.table("links")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )

    links = links_res.data or []

    # ================= TIME =================
    now = datetime.now(timezone.utc)
    today = now.date()
    yesterday = today - timedelta(days=1)

    current_month = now.month
    current_year = now.year

    # ================= INIT =================
    today_clicks = 0
    today_earnings = 0

    month_clicks = 0
    month_earnings = 0

    total_clicks = 0
    total_earnings = 0

    yesterday_clicks = 0
    yesterday_earnings = 0

    # ================= SAFE DATE PARSER =================
    def parse_date(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(
                ts.replace("Z", "+00:00")
            )
        except:
            return None

    # ================= JOIN DATE =================
    join_date = "-"

    if user.get("created_at"):
        created = parse_date(user.get("created_at"))
        if created:
            join_date = created.strftime("%d %B %Y")

    # ================= CALC MAIN STATS =================
    for l in links:
        clicks = l.get("clicks") or 0
        earnings = l.get("earnings") or 0
        created = parse_date(l.get("created_at"))

        total_clicks += clicks
        total_earnings += earnings

        if not created:
            continue

        d = created.date()

        if d == today:
            today_clicks += clicks
            today_earnings += earnings

        if d == yesterday:
            yesterday_clicks += clicks
            yesterday_earnings += earnings

        if created.month == current_month and created.year == current_year:
            month_clicks += clicks
            month_earnings += earnings

    total_links = len(links)

    # ================= REFERRAL =================
    ref_res = (
        supabase.table("referrals")
        .select("referred_user_id")
        .eq("user_id", user_id)
        .execute()
    )

    referred_ids = [
        r.get("referred_user_id")
        for r in (ref_res.data or [])
        if r.get("referred_user_id")
    ]

    active_referrals = 0

    if referred_ids:
        users_res = (
            supabase.table("users")
            .select("clicks")
            .in_("id", referred_ids)
            .execute()
        )

        active_referrals = sum(
            1 for u in (users_res.data or [])
            if (u.get("clicks") or 0) > 0
        )

    # ================= CPM =================
    average_cpm = round(today_earnings / today_clicks, 2) if today_clicks else 0
    month_cpm = round(month_earnings / month_clicks, 2) if month_clicks else 0

    prev_cpm = (yesterday_earnings / yesterday_clicks) if yesterday_clicks else 0
    cpm_growth = round(average_cpm - prev_cpm, 2)

    # ================= GROWTH SAFE DEFAULT =================
    today_growth = today_earnings
    earning_growth = today_earnings

    month_growth = month_earnings
    month_earning_growth = month_earnings
    month_cpm_growth = month_cpm

    # ================= TOTAL USERS =================
    users_res = (
        supabase.table("users")
        .select("id", count="exact")
        .execute()
    )
    total_users = users_res.count or 0

    # ================= CPM BY COUNTRY =================
    cpm_by_country = {}

    try:
        geo_res = (
            supabase.table("clicks_log")
            .select("country,earnings")
            .eq("user_id", user_id)
            .execute()
        )

        geo_map = {}

        for r in geo_res.data or []:
            country = r.get("country") or "Unknown"

            if country not in geo_map:
                geo_map[country] = {
                    "clicks": 0,
                    "earnings": 0
                }

            geo_map[country]["clicks"] += 1
            geo_map[country]["earnings"] += (
                r.get("earnings") or 0
            )

        cpm_by_country = {
            k: (
                v["earnings"] / v["clicks"]
                if v["clicks"] else 0
            )
            for k, v in geo_map.items()
        }

    except:
        cpm_by_country = {}

    # ================= SELLLINK =================
    sell_res = (
        supabase.table("sell_links")
        .select("*")
        .eq("user_id", user_id)
        .execute()
    )

    selllinks = sell_res.data or []

    today_sell_orders = 0
    today_sell_income = 0.0

    yesterday_sell_orders = 0
    yesterday_sell_income = 0.0

    month_sell_orders = 0
    month_sell_income = 0.0

    total_sell_products = len(selllinks)

    for item in selllinks:
        created = parse_date(item.get("created_at"))
        if not created:
            continue

        sold = int(item.get("sold") or 0)
        earnings = float(item.get("earnings") or 0)

        if created.date() == today:
            today_sell_orders += sold
            today_sell_income += earnings

        elif created.date() == yesterday:
            yesterday_sell_orders += sold
            yesterday_sell_income += earnings

        if (
            created.year == current_year
            and created.month == current_month
        ):
            month_sell_orders += sold
            month_sell_income += earnings

    avg_sell_value = (
        round(today_sell_income / today_sell_orders, 2)
        if today_sell_orders > 0
        else 0
    )

    month_avg_order = (
        round(month_sell_income / month_sell_orders, 2)
        if month_sell_orders > 0
        else 0
    )

    month_products_sold = month_sell_orders

    if yesterday_sell_orders > 0:
        today_sell_growth = round(
            (
                (today_sell_orders - yesterday_sell_orders)
                / yesterday_sell_orders
            ) * 100,
            2
        )
    else:
        today_sell_growth = (
            100 if today_sell_orders else 0
        )

    if yesterday_sell_income > 0:
        today_sell_income_growth = round(
            (
                (today_sell_income - yesterday_sell_income)
                / yesterday_sell_income
            ) * 100,
            2
        )
    else:
        today_sell_income_growth = (
            100 if today_sell_income else 0
        )

    month_sell_growth = 0
    month_sell_income_growth = 0

    # ================= 30 HARI CHART =================
    chart_labels = []
    chart_clicks = []
    chart_earnings = []

    sell_order_chart = []
    sell_income_chart = []

    for i in range(29, -1, -1):
        day = today - timedelta(days=i)

        dc = 0
        de = 0
        so = 0
        si = 0

        for l in links:
            created = parse_date(l.get("created_at"))

            if created and created.date() == day:
                dc += l.get("clicks") or 0
                de += l.get("earnings") or 0

        for s in selllinks:
            created = parse_date(s.get("created_at"))

            if created and created.date() == day:
                so += int(s.get("sold") or 0)
                si += float(s.get("earnings") or 0)

        chart_labels.append(day.strftime("%d/%m"))
        chart_clicks.append(dc)
        chart_earnings.append(de)

        sell_order_chart.append(so)
        sell_income_chart.append(si)

    # ================= RENDER =================
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "join_date": join_date,
            "username": user.get("username", ""),
            "saldo": user.get("saldo", 0),

            "total_links": total_links,
            "total_clicks": total_clicks,
            "total_earnings": total_earnings,
            "total_earn": total_earnings,
            "base_url": str(request.base_url).rstrip("/"),

            "today": today.strftime("%d %B %Y"),
            "today_clicks": today_clicks,
            "today_earnings": today_earnings,

            "month_clicks": month_clicks,
            "month_earnings": month_earnings,

            "average_cpm": average_cpm,
            "month_cpm": month_cpm,

            "cpm_growth": cpm_growth,
            "today_growth": today_growth,
            "earning_growth": earning_growth,
            "month_growth": month_growth,
            "month_earning_growth": month_earning_growth,
            "month_cpm_growth": month_cpm_growth,

            "today_sell_orders": today_sell_orders,
            "today_sell_growth": today_sell_growth,
            "today_sell_income": today_sell_income,
            "today_sell_income_growth": today_sell_income_growth,

            "total_sell_products": total_sell_products,
            "avg_sell_value": avg_sell_value,

            "month_sell_orders": month_sell_orders,
            "month_sell_growth": month_sell_growth,
            "month_sell_income": month_sell_income,
            "month_sell_income_growth": month_sell_income_growth,

            "month_products_sold": month_products_sold,
            "month_avg_order": month_avg_order,

            "chart_labels": chart_labels,
            "chart_clicks": chart_clicks,
            "chart_earnings": chart_earnings,
            "sell_order_chart": sell_order_chart,
            "sell_income_chart": sell_income_chart,

            "active_referrals": active_referrals,
            "total_users": total_users,

            "cpm_by_country": cpm_by_country,

            "latest_links": links[:5],
            "links": links,

            "current_month_name": calendar.month_name[current_month],
            "announcement": announcement,
            "unread_count": unread_count,
        },
    )
    
# =========================
# SELL PAGE
# =========================
@app.get("/sell")
async def sell_page(request: Request):

    # ✅ pakai user_id (WAJIB)
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", 303)

    # ✅ ambil user dari DB pakai ID
    user_res = (
        supabase.table("users")
        .select("id, username, saldo")
        .eq("id", user_id)
        .single()
        .execute()
    )

    # ❗ kalau user hilang → logout paksa
    if not user_res.data:
        request.session.clear()
        return RedirectResponse("/login", 303)

    user = user_res.data

    # ✅ ambil sell links
    sell_links_res = (
        supabase.table("sell_links")
        .select("*")
        .eq("user_id", user_id)
        .order("id", desc=True)
        .execute()
    )

    sell_links = sell_links_res.data or []

    # ✅ render
    return templates.TemplateResponse("selllink.html", {
        "request": request,
        "username": user["username"],  # ambil dari DB
        "saldo": user.get("saldo") or 0,
        "sell_links": sell_links,
        "total_links": len(sell_links),
        "total_sold": 0,
        "total_income": 0
    })
    
# =========================
# CREATE SELL LINK
# =========================
@app.post("/create-sell-link")
async def create_sell_link(
    request: Request,
    destination_url: str = Form(...),
    title: str = Form(...),
    price: int = Form(...)
):

    # ✅ pakai user_id
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    # ✅ validasi input
    if not destination_url.startswith("http"):
        return JSONResponse({"ok": False, "error": "invalid_url"}, status_code=400)

    if int(price) <= 0:
        return JSONResponse({"ok": False, "error": "invalid_price"}, status_code=400)

    # ✅ generate code unik (anti bentrok)
    while True:
        code = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        check = (
            supabase.table("sell_links")
            .select("id")
            .eq("code", code)
            .limit(1)
            .execute()
        )

        if not check.data:
            break

    # ✅ insert
    supabase.table("sell_links").insert({
        "user_id": user_id,
        "code": code,
        "title": title.strip(),
        "destination_url": destination_url.strip(),
        "price": int(price),
        "sold": 0,
        "earnings": 0,
    }).execute()

    return JSONResponse({
        "ok": True,
        "link": f"{request.base_url}pay/{code}"
    })
# =========================
# PAY PAGE
# =========================
@app.get("/pay/{code}")
async def pay_page(request: Request, code: str):

    link_res = (
        supabase.table("sell_links")
        .select("*")
        .eq("code", code)
        .single()
        .execute()
    )

    if not link_res.data:
        return HTMLResponse("Not found", 404)

    link = link_res.data

    # optional: bisa cek kalau link nonaktif / harga 0 dll
    if link.get("price", 0) <= 0:
        return HTMLResponse("Invalid link", 400)

    return templates.TemplateResponse("pay.html", {
        "request": request,
        "link": link
    })
# =========================
# DELETE SELL LINK
# =========================
@app.delete("/delete-sell-link/{code}")
async def delete_sell_link(request: Request, code: str):

    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(
            {"ok": False, "error": "Unauthorized"},
            status_code=401
        )

    link = (
        supabase.table("sell_links")
        .select("id")
        .eq("code", code)
        .eq("user_id", user_id)
        .single()
        .execute()
    )

    if not link.data:
        return JSONResponse(
            {"ok": False, "error": "Link not found"},
            status_code=404
        )

    supabase.table("sell_links") \
        .delete() \
        .eq("id", link.data["id"]) \
        .execute()

    return JSONResponse({"ok": True})
@app.post("/delete-link/{id}")
async def delete_link(request: Request, id: int):

    user_id = request.session.get("user_id")

    if not user_id:
        return JSONResponse(
            {"ok": False, "error": "Unauthorized"},
            status_code=401
        )

    try:
        # Pastikan link milik user
        link = (
            supabase.table("links")
            .select("id")
            .eq("id", id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )

        if not link.data:
            return JSONResponse(
                {"ok": False, "error": "Link tidak ditemukan"},
                status_code=404
            )

        supabase.table("links")\
            .delete()\
            .eq("id", id)\
            .execute()

        return JSONResponse({"ok": True})

    except Exception as e:
        print("DELETE ERROR:", e)
        return JSONResponse(
            {"ok": False, "error": str(e)},
            status_code=500
        )

# =========================
# EDIT ADS LINK
# =========================
@app.post("/edit-link/{id}")
async def edit_link(id: int, url: str = Form(...)):
    try:
        supabase.table("links").update({
            "destination_url": url
        }).eq("id", id).execute()

        return {"ok": True}

    except Exception as e:
        print("ERROR EDIT ADS:", e)
        return {"ok": False, "error": str(e)}

# =========================
# EDIT SELL LINK
# =========================
@app.post("/edit-sell-link/{id}")
async def edit_sell_link(
    request: Request,
    id: int,
    url: str = Form(...),
    price: int = Form(...)
):
    try:
        username = request.session.get("username")
        if not username:
            return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=401)

        supabase.table("sell_links").update({
            "destination_url": url,
            "price": price
        }).eq("id", id).execute()

        return {"ok": True}

    except Exception as e:
        print("ERROR EDIT SELL:", e)
        return {"ok": False, "error": str(e)}
# =========================
# CREATE SHORT LINK
# =========================
@app.post("/create-link")
async def create_link(
    request: Request,
    destination_url: str = Form(...),
    title: str = Form(...)
):

    # LOGIN CHECK
    user_id = request.session.get("user_id")

    if not user_id:
        return JSONResponse(
            {"ok": False, "error": "Unauthorized"},
            status_code=401
        )

    # VALIDASI URL
    destination_url = destination_url.strip()

    if not (
        destination_url.startswith("http://")
        or destination_url.startswith("https://")
    ):
        destination_url = "https://" + destination_url

    # GENERATE SHORT CODE
    while True:
        short_code = "".join(
            random.choices(
                string.ascii_letters + string.digits,
                k=8
            )
        )

        check = (
            supabase.table("links")
            .select("id")
            .eq("short_code", short_code)
            .limit(1)
            .execute()
        )

        if not check.data:
            break

    # INSERT DATABASE
    insert = (
        supabase.table("links")
        .insert({
            "user_id": user_id,
            "title": title.strip(),
            "destination_url": destination_url,
            "short_code": short_code,
            "clicks": 0,
            "earnings": 0,
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        .execute()
    )

    if not insert.data:
        return JSONResponse(
            {"ok": False, "error": "Failed create link"},
            status_code=500
        )

    short_url = f"{request.base_url}s/{short_code}"

    return JSONResponse({
        "ok": True,
        "title": title,
        "short_code": short_code,
        "short_url": short_url,
        "destination_url": destination_url
    })
# =========================
# SHORTLINK
# =========================
@app.get("/s/{short_code}")
async def shortlink(request: Request, short_code: str):

    try:
        # =========================
        # GET LINK
        # =========================
        res = (
            supabase.table("links")
            .select("*")
            .eq("short_code", short_code)
            .limit(1)
            .execute()
        )

        if not res.data:
            return HTMLResponse("Link tidak ditemukan", 404)

        link = res.data[0]

        if not link:
            return HTMLResponse("Link tidak valid", 404)

        if link.get("is_active") is False:
            return HTMLResponse("Link tidak aktif", 403)

        link_id = link["id"]
        current_clicks = link.get("clicks") or 0

        # =========================
        # UPDATE CLICK (SAFE)
        # =========================
        supabase.table("links").update({
            "clicks": current_clicks + 1
        }).eq("id", link_id).execute()

        # =========================
        # GENERATE TOKEN
        # =========================
        token = secrets.token_urlsafe(32)

        insert_token = supabase.table("download_tokens").insert({
            "token": token,
            "short_code": short_code,
            "step": 1,
            "used": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        }).execute()

        # =========================
        # CHECK INSERT SUCCESS
        # =========================
        if not insert_token.data:
            print("TOKEN INSERT FAILED:", insert_token)
            return HTMLResponse("Gagal membuat session task", 500)

        # =========================
        # DEBUG LOG (WAJIB SEMENTARA)
        # =========================
        print("SHORTLINK HIT:", short_code)
        print("TOKEN CREATED:", token)

        # =========================
        # RENDER TASK1
        # =========================
        return templates.TemplateResponse("task1.html", {
            "request": request,
            "token": token,
            "destination_url": link.get("destination_url"),
            "title": link.get("title", "")
        })

    except Exception as e:
        print("ERROR SHORTLINK:", str(e))
        traceback.print_exc()
        return HTMLResponse("Internal Server Error", 500)


# =========================
# TASK2
# ========================

@app.get("/task2/{token}")
async def task2(request: Request, token: str):

    username = request.session.get("username")
    user_id = request.session.get("user_id")

    # =========================
    # AUTH CHECK
    # =========================
    if not username or not user_id:
        return HTMLResponse("Unauthorized", 401)

    # =========================
    # GET TOKEN DATA
    # =========================
    try:
        token_res = (
            supabase.table("download_tokens")
            .select("*")
            .eq("token", token)
            .limit(1)
            .execute()
        )

    except Exception as e:
        print("DB ERROR TASK2:", e)
        return HTMLResponse("Server error", 500)

    # =========================
    # TOKEN VALIDATION
    # =========================
    if not token_res.data:
        print("TASK2 DENIED: token not found")
        return HTMLResponse("Access denied (token not found)", 403)

    data = token_res.data[0]

    # =========================
    # SAFE DEFAULTS
    # =========================
    step = int(data.get("step") or 0)
    used = bool(data.get("used") or False)

    short_code = data.get("short_code")

    # =========================
    # HARD SECURITY CHECK
    # =========================
    if used:
        print("TASK2 DENIED: token already used")
        return HTMLResponse("Access denied (token used)", 403)

    if step < 1:
        print(f"TASK2 DENIED: invalid step ({step})")
        return HTMLResponse("Access denied (invalid flow)", 403)

    # =========================
    # USER BINDING (ANTI COPY TOKEN)
    # =========================
    if data.get("user_id") and data["user_id"] != user_id:
        print("TASK2 DENIED: user mismatch")
        return HTMLResponse("Access denied (invalid user)", 403)

    # =========================
    # SHORTLINK CHECK
    # =========================
    try:
        link_check = (
            supabase.table("links")
            .select("id")
            .eq("short_code", short_code)
            .limit(1)
            .execute()
        )

    except Exception as e:
        print("LINK CHECK ERROR:", e)
        return HTMLResponse("Server error", 500)

    if not link_check.data:
        print("TASK2 DENIED: shortlink missing")
        return HTMLResponse("Access denied (link missing)", 403)

    # =========================
    # 🔒 AUTO RECOVERY (FIX STUCK STEP)
    # =========================
    if step == 0:
        supabase.table("download_tokens") \
            .update({"step": 1}) \
            .eq("token", token) \
            .execute()
        step = 1

    # =========================
    # DEBUG LOG
    # =========================
    print("TASK2 OK:", {
        "token": token,
        "step": step,
        "user": username
    })

    # =========================
    # RENDER TASK2
    # =========================
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
async def complete_task2(request: Request, token: str = Form(...)):

    username = request.session.get("username")
    user_id = request.session.get("user_id")

    if not username or not user_id:
        return HTMLResponse("Unauthorized", 401)

    token_res = (
        supabase.table("download_tokens")
        .select("*")
        .eq("token", token)
        .limit(1)
        .execute()
    )

    if not token_res.data:
        return HTMLResponse("Invalid Token", 403)

    token_row = token_res.data[0]

    step = int(token_row.get("step") or 0)
    used = bool(token_row.get("used") or False)

    if used:
        return HTMLResponse("Token already used", 403)

    # Kalau sudah di task3, langsung lanjut
    if step >= 2:
        return RedirectResponse(f"/task3/{token}", status_code=303)

    if step < 1:
        return HTMLResponse("Invalid Step", 403)

    update = (
        supabase.table("download_tokens")
        .update({
            "step": 2
        })
        .eq("token", token)
        .eq("step", 1)
        .eq("used", False)
        .execute()
    )

    if not update.data:
        return RedirectResponse(f"/task3/{token}", status_code=303)

    return RedirectResponse(f"/task3/{token}", status_code=303)


# =========================
# TASK3
# =========================
@app.get("/task3/{token}")
async def task3(request: Request, token: str):

    username = request.session.get("username")
    user_id = request.session.get("user_id")

    if not username or not user_id:
        return HTMLResponse("Unauthorized", 401)

    # =========================
    # GET TOKEN
    # =========================
    try:
        res = supabase.table("download_tokens") \
            .select("*") \
            .eq("token", token) \
            .limit(1) \
            .execute()

    except Exception as e:
        print("DB ERROR TASK3:", e)
        return HTMLResponse("Server error", 500)

    if not res.data:
        return HTMLResponse("Access denied (invalid token)", 403)

    token_row = res.data[0]

    # =========================
    # SAFE DEFAULTS
    # =========================
    step = token_row.get("step") or 0
    used = token_row.get("used") or False

    # =========================
    # VALIDATION STRICT
    # =========================
    if used:
        return HTMLResponse("Access denied (used token)", 403)

    if step != 2:
        print("TASK3 DENIED: wrong step", step)
        return HTMLResponse("Access denied (invalid step)", 403)

    # =========================
    # LINK CHECK
    # =========================
    link_check = supabase.table("links") \
        .select("id") \
        .eq("short_code", token_row["short_code"]) \
        .limit(1) \
        .execute()

    if not link_check.data:
        return HTMLResponse("Access denied (link missing)", 403)

    # =========================
    # RENDER
    # =========================
    return templates.TemplateResponse(
        "task3.html",
        {
            "request": request,
            "token": token
        }
    )


from fastapi.responses import HTMLResponse, JSONResponse

@app.post("/complete-task3")
async def complete_task3(request: Request, token: str = Form(...)):

    print("\n========== COMPLETE TASK3 ==========")
    print("TOKEN:", token)

    username = request.session.get("username")
    user_id = request.session.get("user_id")

    print("USERNAME:", username)
    print("USER ID :", user_id)

    if not username or not user_id:
        return HTMLResponse("Unauthorized", 401)

    # =========================
    # GET TOKEN
    # =========================
    try:
        res = (
            supabase.table("download_tokens")
            .select("*")
            .eq("token", token)
            .limit(1)
            .execute()
        )

    except Exception as e:
        print("DB ERROR:", e)
        return HTMLResponse(f"DB ERROR : {e}", 500)

    if not res.data:
        print("TOKEN TIDAK DITEMUKAN")
        return HTMLResponse("DEBUG : Token tidak ditemukan", 403)

    token_row = res.data[0]

    print("TOKEN ROW:", token_row)

    step = int(token_row.get("step") or 0)
    used = bool(token_row.get("used") or False)

    print("STEP :", step)
    print("USED :", used)

    # =========================
    # VALIDASI LINK
    # =========================
    link = (
        supabase.table("links")
        .select("id")
        .eq("short_code", token_row["short_code"])
        .limit(1)
        .execute()
    )

    print("LINK:", link.data)

    if not link.data:
        return HTMLResponse("DEBUG : Link tidak ditemukan", 403)

    # =========================
    # CEK STEP
    # =========================
    if step != 2:
        return HTMLResponse(
            f"DEBUG : Step salah. Step sekarang = {step}",
            403
        )

    # =========================
    # CEK USED
    # =========================
    if used:
        return HTMLResponse(
            "DEBUG : Token sudah digunakan (used=True)",
            403
        )

    # =========================
    # UPDATE
    # =========================
    update = (
        supabase.table("download_tokens")
        .update({
            "step": 3,
            "used": True
        })
        .eq("token", token)
        .eq("step", 2)
        .eq("used", False)
        .execute()
    )

    print("UPDATE RESULT:", update.data)

    if not update.data:
        return HTMLResponse(
            "DEBUG : Update gagal (kemungkinan request dikirim dua kali)",
            409
        )

    print("TASK3 BERHASIL")

    return JSONResponse({
        "success": True
    })
# =========================
# FINAL REWARD
# =========================

@app.post("/final-reward")
async def final_reward(request: Request, token: str = Form(...)):

    user_id = request.session.get("user_id")
    if not user_id:
        return HTMLResponse("Unauthorized", 401)

    # ================= TOKEN SAFE FETCH =================
    token_res = (
        supabase.table("download_tokens")
        .select("*")
        .eq("token", token)
        .limit(1)
        .execute()
    )

    token_data = token_res.data[0] if token_res.data else None
    if not token_data:
        return HTMLResponse("Invalid Token", 403)

    # ================= STATUS CHECK =================
    if token_data.get("used") is not True:
        return HTMLResponse("Task belum selesai", 403)

    if token_data.get("rewarded") is True:
        return HTMLResponse("Already claimed", 403)

    short_code = token_data.get("short_code")
    if not short_code:
        return HTMLResponse("Invalid short_code", 400)

    # ================= LINK SAFE FETCH =================
    link_res = (
        supabase.table("links")
        .select("destination_url, user_id")
        .eq("short_code", short_code)
        .limit(1)
        .execute()
    )

    link_data = link_res.data[0] if link_res.data else None
    if not link_data:
        return HTMLResponse("Link not found", 404)

    owner_id = link_data.get("user_id")
    destination_url = link_data.get("destination_url")

    if not owner_id or not destination_url:
        return HTMLResponse("Broken link data", 500)

    reward = 165
    commission = int(reward * 0.10)

    # ================= ATOMIC CLAIM (ANTI DOUBLE CLICK) =================
    update_res = (
        supabase.table("download_tokens")
        .update({"rewarded": True})
        .eq("token", token)
        .eq("rewarded", False)
        .execute()
    )

    # kalau tidak ada row yang berubah → sudah diklaim
    if not update_res.data:
        return HTMLResponse("Already claimed", 403)

    # ================= OWNER BALANCE SAFE RPC =================
    try:
        supabase.rpc(
            "increment_user_balance",
            {
                "uid": owner_id,   # HARUS SAMA TIPE DI DB (UUID / TEXT)
                "amount": reward
            }
        ).execute()
    except Exception as e:
        # rollback mindset (opsional log)
        return HTMLResponse(f"Reward error: {str(e)}", 500)

    # ================= REFERRAL SAFE =================
    ref_res = (
        supabase.table("referrals")
        .select("user_id")
        .eq("referred_user_id", owner_id)
        .limit(1)
        .execute()
    )

    ref_data = ref_res.data[0] if ref_res.data else None

    if ref_data and ref_data.get("user_id"):
        referrer_id = ref_data["user_id"]

        try:
            supabase.rpc(
                "increment_user_balance",
                {
                    "uid": referrer_id,
                    "amount": commission
                }
            ).execute()
        except:
            pass  # jangan ganggu flow utama

    return RedirectResponse(destination_url, 303)
# =========================
# LINKS
# =========================


from math import ceil
from fastapi import Request, Query
from fastapi.responses import RedirectResponse

@app.get("/links")
async def links(
    request: Request,
    page: int = Query(1, ge=1),
    tab: str = Query("ads")   # ✅ FIX 1: TAMBAH TAB
):

    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", 303)

    # ================= USER =================
    user = (
        supabase.table("users")
        .select("username, saldo, has_withdraw")
        .eq("id", user_id)
        .limit(1)
        .execute()
    )

    user_data = (user.data or [{}])[0]

    # ================= FETCH DATA =================
    links_res = (
        supabase.table("links")
        .select("*")
        .eq("user_id", user_id)
        .order("id", desc=True)
        .execute()
    )

    sell_res = (
        supabase.table("sell_links")
        .select("*")
        .eq("user_id", user_id)
        .order("id", desc=True)
        .execute()
    )

    links_data = links_res.data or []
    sell_links = sell_res.data or []

    # ================= NORMALIZE =================
    for link in links_data:
        link["price"] = 0
        link["type"] = "ads"

    for link in sell_links:
        link["price"] = link.get("price", 0)
        link["type"] = "sell"

    # ================= FILTER BY TAB =================
    if tab == "ads":
        filtered = links_data
    else:
        filtered = sell_links

    # ================= PAGINATION =================
    per_page = 5
    total_links = len(filtered)
    total_pages = max(1, ceil(total_links / per_page))

    page = max(1, min(page, total_pages))

    start = (page - 1) * per_page
    end = start + per_page

    paginated_links = filtered[start:end]   # ✅ FIX 2 (end tanpa -1)

    # ================= STATS =================
    total_clicks = sum(l.get("clicks") or 0 for l in links_data + sell_links)
    total_earnings = sum(l.get("earnings") or 0 for l in links_data + sell_links)

    # ================= NAV =================
    has_prev = page > 1
    has_next = page < total_pages

    # ================= RETURN =================
    return templates.TemplateResponse(
        "links.html",
        {
            "request": request,
            "tab": tab,   # ✅ FIX 3: SEKARANG AMAN
            "user": user,
            "user_data": user_data,

            # pagination sudah sesuai tab
            "ads_links_page": paginated_links if tab == "ads" else [],
            "sell_links_page": paginated_links if tab == "sell" else [],

            "base_url": str(request.base_url).rstrip("/"),

            "total_links": total_links,
            "total_clicks": total_clicks,
            "total_earnings": total_earnings,

            "saldo": user_data.get("saldo") or 0,
            "username": user_data.get("username") or "",

            "page": page,
            "total_pages": total_pages,
            "has_prev": has_prev,
            "has_next": has_next,
        }
    )

@app.get("/settings")
async def settings(request: Request):

    username = request.session.get("username")

    if not username:
        return RedirectResponse("/login", 303)

    result = (
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .single()
        .execute()
    )

    if not result.data:
        return RedirectResponse("/login", 303)

    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "username": username,
            "saldo": result.data.get("saldo") or 0,
            "user": result.data
        }
    )


@app.post("/settings/profile")
async def update_profile(request: Request, username: str = Form(...)):
    user_id = request.session.get("user_id")

    supabase.table("users")\
        .update({"username": username})\
        .eq("id", user_id)\
        .execute()

    return RedirectResponse("/settings", status_code=303)

@app.post("/settings/password")
async def update_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    user_id = request.session.get("user_id")

    user = supabase.table("users")\
        .select("*")\
        .eq("id", user_id)\
        .single()\
        .execute().data

    if not verify_password(old_password, user["password"]):
        return RedirectResponse("/settings?error=wrong_password", 303)

    if new_password != confirm_password:
        return RedirectResponse("/settings?error=not_match", 303)

    supabase.table("users")\
        .update({"password": hash_password(new_password)})\
        .eq("id", user_id)\
        .execute()

    return RedirectResponse("/settings?success=password", 303)

@app.post("/settings/payment")
async def update_payment(
    request: Request,
    payment_name: str = Form(None),
    payment_method: str = Form(None),
    payment_number: str = Form(None),
):
    user_id = request.session.get("user_id")

    supabase.table("users").update({
        "payment_name": payment_name,
        "payment_method": payment_method,
        "payment_number": payment_number
    }).eq("id", user_id).execute()

    return RedirectResponse("/settings?success=payment", 303)

@app.post("/settings/shortlink")
async def update_shortlink(
    request: Request,
    default_title: str = Form(None),
    monetization: str = Form(None)
):
    user_id = request.session.get("user_id")

    supabase.table("users").update({
        "default_title": default_title,
        "monetization": monetization
    }).eq("id", user_id).execute()

    return RedirectResponse("/settings?success=shortlink", 303)

@app.post("/settings/notification")
async def update_notification(
    request: Request,
    email_notification: str = Form(...),
    withdraw_notification: str = Form(...),
    referral_notification: str = Form(...),
    announcement_notification: str = Form(...)
):
    user_id = request.session.get("user_id")

    supabase.table("users").update({
        "email_notification": email_notification,
        "withdraw_notification": withdraw_notification,
        "referral_notification": referral_notification,
        "announcement_notification": announcement_notification
    }).eq("id", user_id).execute()

    return RedirectResponse("/settings?success=notif", 303)

import secrets

@app.post("/settings/regenerate-api")
async def regenerate_api(request: Request):
    user_id = request.session.get("user_id")

    new_key = secrets.token_hex(24)

    supabase.table("users")\
        .update({"api_key": new_key})\
        .eq("id", user_id)\
        .execute()

    return RedirectResponse("/settings?success=api", 303)

@app.post("/delete-account")
async def delete_account(request: Request):
    user_id = request.session.get("user_id")

    supabase.table("users")\
        .delete()\
        .eq("id", user_id)\
        .execute()

    request.session.clear()
    return RedirectResponse("/", 303)

@app.get("/privacy")
async def privacy(request: Request):
    return templates.TemplateResponse(
        "privacy.html",
        {"request": request}
    )

@app.get("/terms")
async def terms(request: Request):
    return templates.TemplateResponse(
        "terms.html",
        {"request": request}
    )
# =========================
# LOGOUT
# =========================
@app.get("/logout")
async def logout(request: Request):
    user_id = request.session.get("user_id")

    if user_id:
        supabase.table("users").update({
            "session_token": None
        }).eq("id", user_id).execute()

    request.session.clear()

    response = RedirectResponse("/login", 303)
    response.delete_cookie("session_token")
    return response


# =========================
# ADMIN HELPER
# =========================
def get_admin(request: Request):
    user_id = request.session.get("user_id")

    if not user_id:
        return None

    res = (
        supabase.table("users")
        .select("*")
        .eq("id", user_id)
        .single()
        .execute()
    )

    if not res.data:
        return None

    user = res.data

    if not user.get("is_admin"):
        return None

    return user


# =========================
# ADMIN DASHBOARD
# =========================
@app.get("/admin")
async def admin_dashboard(request: Request):

    admin = get_admin(request)

    if not admin:
        return RedirectResponse("/dashboard", status_code=303)

    # ================= STATISTIK =================
    total_users = (
        supabase.table("users")
        .select("id", count="exact")
        .execute()
    ).count or 0

    total_links = (
        supabase.table("links")
        .select("id", count="exact")
        .execute()
    ).count or 0

    total_sell_links = (
        supabase.table("sell_links")
        .select("id", count="exact")
        .execute()
    ).count or 0

    # ================= WITHDRAW PENDING =================
    try:
        withdraw_pending = (
            supabase.table("withdrawals")
            .select("id", count="exact")
            .eq("status", "pending")
            .execute()
        ).count or 0
    except:
        withdraw_pending = 0

    # ================= USERS =================
    users_res = (
        supabase.table("users")
        .select("*")
        .order("id", desc=True)
        .execute()
    )

    users = users_res.data or []

    # ================= TOTAL SALDO =================
    total_saldo = sum(u.get("saldo") or 0 for u in users)

    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "admin": admin,

            "total_users": total_users,
            "total_links": total_links,
            "total_sell_links": total_sell_links,

            "withdraw_pending": withdraw_pending,

            "total_saldo": total_saldo,
            "users": users
        }
    )
@app.get("/admin/ban/{user_id}")
async def ban_user(request: Request, user_id: str):

    admin_id = request.session.get("user_id")

    if not admin_id:
        return RedirectResponse("/login", 303)

    admin = (
        supabase.table("users")
        .select("is_admin")
        .eq("id", admin_id)
        .single()
        .execute()
    )

    if not admin.data or not admin.data["is_admin"]:
        return HTMLResponse("Access Denied", 403)

    supabase.table("users").update({
        "is_banned": True
    }).eq("id", user_id).execute()

    return RedirectResponse("/admin", 303)
@app.get("/admin/unban/{user_id}")
async def unban_user(request: Request, user_id: str):

    admin_id = request.session.get("user_id")

    if not admin_id:
        return RedirectResponse("/login", 303)

    admin = (
        supabase.table("users")
        .select("is_admin")
        .eq("id", admin_id)
        .single()
        .execute()
    )

    if not admin.data or not admin.data["is_admin"]:
        return HTMLResponse("Access Denied", 403)

    supabase.table("users").update({
        "is_banned": False
    }).eq("id", user_id).execute()

    return RedirectResponse("/admin", 303)
@app.get("/admin/delete-user/{user_id}")
async def delete_user(request: Request, user_id: str):

    admin_id = request.session.get("user_id")

    if not admin_id:
        return RedirectResponse("/login", 303)

    admin = (
        supabase.table("users")
        .select("is_admin")
        .eq("id", admin_id)
        .single()
        .execute()
    )

    if not admin.data or not admin.data["is_admin"]:
        return HTMLResponse("Access Denied", 403)

    supabase.table("links")\
        .delete()\
        .eq("user_id", user_id)\
        .execute()

    supabase.table("sell_links")\
        .delete()\
        .eq("user_id", user_id)\
        .execute()

    supabase.table("referrals")\
        .delete()\
        .eq("referred_user_id", user_id)\
        .execute()

    supabase.table("users")\
        .delete()\
        .eq("id", user_id)\
        .execute()

    return RedirectResponse("/admin", 303)
# === 🆗 ADMIN WD PANEL
from math import ceil
from fastapi import Query

@app.get("/admin/withdraw")
async def admin_withdraw(
    request: Request,
    page: int = Query(1, ge=1),
    status: str | None = None,
    search: str | None = None
):

    admin = get_admin(request)
    if not admin:
        return RedirectResponse("/dashboard", 303)

    per_page = 10

    query = supabase.table("withdrawals").select("*", count="exact")

    # ================= FILTER STATUS =================
    if status:
        query = query.eq("status", status)

    # ================= SEARCH USER =================
    if search:
        users = (
            supabase.table("users")
            .select("id")
            .ilike("username", f"%{search}%")
            .execute()
        ).data or []

        user_ids = [u["id"] for u in users]

        if user_ids:
            query = query.in_("user_id", user_ids)
        else:
            query = query.eq("user_id", -1)  # kosongkan hasil

    # ================= COUNT =================
    count_res = query.execute()
    total = count_res.count or 0

    total_pages = max(1, ceil(total / per_page))

    if page < 1:
        page = 1
    if page > total_pages:
        page = total_pages

    start = (page - 1) * per_page
    end = start + per_page - 1

    # ================= DATA =================
    data_res = (
        supabase.table("withdrawals")
        .select("*")
        .order("id", desc=True)
        .range(start, end)
        .execute()
    )

    withdraws = data_res.data or []

    return templates.TemplateResponse(
        "admin_withdraw.html",
        {
            "request": request,
            "admin": admin,
            "withdraws": withdraws,

            "page": page,
            "total_pages": total_pages,
            "status": status,
            "search": search or ""
        }
    )
@app.get("/admin/withdraw/approve/{withdraw_id}")
async def approve_withdraw(request: Request, withdraw_id: int):

    admin = get_admin(request)
    if not admin:
        return RedirectResponse("/dashboard", 303)

    w = get_withdraw(withdraw_id)
    if not w:
        return RedirectResponse("/admin/withdraw", 303)

    # anti double approve
    if w["status"] != "process":
        return RedirectResponse("/admin/withdraw", 303)

    supabase.table("withdrawals").update({
        "status": "approved"
    }).eq("id", withdraw_id).execute()

    return RedirectResponse("/admin/withdraw", 303)
@app.get("/admin/withdraw/process/{withdraw_id}")
async def process_withdraw(request: Request, withdraw_id: int):

    admin = get_admin(request)
    if not admin:
        return RedirectResponse("/dashboard", 303)

    w = get_withdraw(withdraw_id)
    if not w:
        return RedirectResponse("/admin/withdraw", 303)

    # anti double action
    if w["status"] != "pending":
        return RedirectResponse("/admin/withdraw", 303)

    supabase.table("withdrawals").update({
        "status": "process"
    }).eq("id", withdraw_id).execute()

    return RedirectResponse("/admin/withdraw", 303)
@app.get("/admin/withdraw/reject/{withdraw_id}")
async def reject_withdraw(request: Request, withdraw_id: int):

    admin = get_admin(request)
    if not admin:
        return RedirectResponse("/dashboard", 303)

    w = get_withdraw(withdraw_id)
    if not w:
        return RedirectResponse("/admin/withdraw", 303)

    # anti double reject
    if w["status"] == "rejected":
        return RedirectResponse("/admin/withdraw", 303)

    # ================= ROLLBACK SALDO =================
    user = (
        supabase.table("users")
        .select("saldo")
        .eq("id", w["user_id"])
        .single()
        .execute()
    ).data

    if user:
        current_saldo = user.get("saldo") or 0

        supabase.table("users").update({
            "saldo": current_saldo + w["amount"]
        }).eq("id", w["user_id"]).execute()

    # update status
    supabase.table("withdrawals").update({
        "status": "rejected"
    }).eq("id", withdraw_id).execute()

    return RedirectResponse("/admin/withdraw", 303)


from fastapi.responses import HTMLResponse
@app.get("/oauth-error")
async def oauth_error():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <title>Login Google Gagal</title>
        <style>
            body{
                margin:0;
                background:#0f172a;
                color:#fff;
                font-family:Arial,sans-serif;
                display:flex;
                justify-content:center;
                align-items:center;
                height:100vh;
            }
            .card{
                width:90%;
                max-width:500px;
                background:#1e293b;
                padding:35px;
                border-radius:20px;
                text-align:center;
                box-shadow:0 15px 35px rgba(0,0,0,.4);
            }
            h1{
                color:#ef4444;
                margin-bottom:15px;
            }
            p{
                color:#cbd5e1;
                line-height:1.7;
            }
            .uri{
                margin:20px 0;
                padding:12px;
                background:#0f172a;
                border-radius:10px;
                word-break:break-all;
                color:#38bdf8;
            }
            a{
                display:inline-block;
                margin-top:20px;
                padding:12px 25px;
                background:#2563eb;
                color:#fff;
                text-decoration:none;
                border-radius:10px;
            }
            a:hover{
                background:#1d4ed8;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>❌ Login Google Gagal</h1>
            <p>
                Terjadi kesalahan konfigurasi OAuth Google
                (<b>redirect_uri_mismatch</b>).
            </p>
            <p>
                Pastikan URL berikut sudah ditambahkan
                pada Google Cloud Console:
            </p>
            <div class="uri">
                https://eslink.up.railway.app/auth/callback
            </div>
            <a href="/login">Kembali ke Login</a>
        </div>
    </body>
    </html>
    """)
# =========================
# FAVICON
# =========================
@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)
