import calendar
import os
import random
import secrets
import string
from datetime import datetime, timezone

from fastapi import (
    Body,
    FastAPI,
    Form,
    Request,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from auth import hash_password, verify_password
from database import supabase

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

    # referral dari session
    referral = request.session.get("referral")

    # buat akun baru
    supabase.table("users").insert({
        "gmail": gmail,
        "username": username,
        "password": hash_password(password),
        "saldo": 0,
        "total_earn": 0,
        "referrals": 0,
        "is_banned": False
    }).execute()

    # ambil id user yang baru dibuat
    new_user = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .single()
        .execute()
    )

    new_user_id = new_user.data["id"]

    # ==========================
    # REFERRAL
    # ==========================
    if referral:

        ref = (
            supabase.table("users")
            .select("id,saldo,referrals")
            .eq("username", referral)
            .single()
            .execute()
        )

        if ref.data:

            referrer = ref.data
            referrer_id = referrer["id"]

            # simpan relasi referral
            supabase.table("referrals").insert({
                "user_id": referrer_id,
                "referred_user_id": new_user_id,
                "referral_paid": False
            }).execute()

            # bonus pendaftar
            supabase.table("users").update({
                "saldo": (referrer["saldo"] or 0) + 500,
                "referrals": (referrer["referrals"] or 0) + 1
            }).eq("id", referrer_id).execute()

        request.session.pop("referral", None)

    # login otomatis
    request.session["username"] = username

    return RedirectResponse("/dashboard", status_code=303)

# =========================
# DASHBOARD
# =========================

@app.get("/dashboard")
async def dashboard(request: Request):
    username = request.session.get("username")
    if not username:
        return RedirectResponse("/login", status_code=303)

    # ================= USER =================
    result = (
        supabase.table("users")
        .select("*")
        .eq("username", username)
        .single()
        .execute()
    )

    if not result.data:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    user = result.data

    if user.get("is_banned"):
        request.session.clear()
        return RedirectResponse("/login?error=banned", status_code=303)

    user_id = user["id"]

    # ================= LINKS =================
    links_res = (
        supabase.table("links")
        .select("*")
        .eq("user_id", user_id)
        .order("id", desc=True)
        .execute()
    )

    links = links_res.data or []

    # ================= TIME =================
    today = datetime.now(timezone.utc).date()
    current_month = today.month
    current_year = today.year

    today_clicks = 0
    today_earnings = 0
    month_clicks = 0
    month_earnings = 0

    def parse_date(ts):
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except:
            return None

    # ================= HITUNG DATA =================
    for link in links:
        clicks = link.get("clicks") or 0
        earnings = link.get("earnings") or 0
        created = parse_date(link.get("created_at"))

        if created:
            if created.date() == today:
                today_clicks += clicks
                today_earnings += earnings

            if created.month == current_month and created.year == current_year:
                month_clicks += clicks
                month_earnings += earnings

    total_links = len(links)
    total_clicks = sum(link.get("clicks") or 0 for link in links)
    total_earnings = sum(link.get("earnings") or 0 for link in links)

    # ================= REFERRAL =================
    ref_res = (
        supabase.table("referrals")
        .select("referred_user_id")
        .eq("user_id", user_id)
        .execute()
    )

    referrals = ref_res.data or []

    referred_ids = list({
        r["referred_user_id"]
        for r in referrals
        if r.get("referred_user_id")
    })

    active_referrals = 0

    if referred_ids:
        users_res = (
            supabase.table("users")
            .select("id,clicks")
            .in_("id", referred_ids)
            .execute()
        )

        for u in (users_res.data or []):
            if (u.get("clicks") or 0) > 0:
                active_referrals += 1

    # ================= REFERRAL EARNINGS =================
    ref_data = (
        supabase.table("users")
        .select("referral_earnings")
        .eq("id", user_id)
        .single()
        .execute()
    )

    referral_earnings = ref_data.data.get("referral_earnings") or 0

    supabase.table("users").update({
        "referral_earnings": referral_earnings
    }).eq("id", user_id).execute()

    # ================= REPORT =================
    today_growth = 0
    earning_growth = 0
    month_growth = 0
    month_earning_growth = 0

    today_referrals = active_referrals
    month_referrals = active_referrals

    average_cpm = round(today_earnings / today_clicks, 2) if today_clicks else 0
    month_cpm = round(month_earnings / month_clicks, 2) if month_clicks else 0

    cpm_growth = 0
    month_cpm_growth = 0

    # ================= CHART =================
    chart_labels = []
    chart_clicks = []
    chart_earnings = []

    recent_links = sorted(
        links,
        key=lambda x: x.get("created_at") or ""
    )[-7:]

    for link in recent_links:
        created = parse_date(link.get("created_at"))

        if created:
            chart_labels.append(created.strftime("%d/%m"))
        else:
            chart_labels.append("-")

        chart_clicks.append(link.get("clicks") or 0)
        chart_earnings.append(link.get("earnings") or 0)

    # ================= RENDER =================
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "username": user["username"],
            "saldo": user.get("saldo") or 0,
            "total_links": total_links,
            "total_clicks": total_clicks,
            "total_earnings": total_earnings,
            "today": today.strftime("%d %B %Y"),
            "today_clicks": today_clicks,
            "today_earnings": today_earnings,
            "today_growth": today_growth,
            "today_referrals": today_referrals,
            "earning_growth": earning_growth,
            "average_cpm": average_cpm,
            "cpm_growth": cpm_growth,
            "month_clicks": month_clicks,
            "month_earnings": month_earnings,
            "month_growth": month_growth,
            "month_earning_growth": month_earning_growth,
            "month_referrals": month_referrals,
            "month_cpm": month_cpm,
            "month_cpm_growth": month_cpm_growth,
            "chart_labels": chart_labels,
            "chart_clicks": chart_clicks,
            "chart_earnings": chart_earnings,
            "latest_links": links[:5],
            "links": links,
            "active_referrals": active_referrals,
            "referral_earnings": referral_earnings,
            "referral_code": user["username"],
            "current_month_name": calendar.month_name[current_month],
        },
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
            "created_at": datetime.now(timezone.utc).isoformat()
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

    token_data = token_res.data[0]

    short_code = token_data["short_code"]

    link = (
        supabase.table("links")
        .select("user_id")
        .eq("short_code", short_code)
        .single()
        .execute()
    )

    if not link.data:
        return HTMLResponse("Link not found", 404)

    owner_id = link.data["user_id"]

    owner = (
        supabase.table("users")
        .select("saldo,total_earn")
        .eq("id", owner_id)
        .single()
        .execute()
    )

    if not owner.data:
        return HTMLResponse("User not found", 404)

    # =========================
    # REWARD PEMILIK LINK
    # =========================

    reward = 300

    saldo = owner.data.get("saldo") or 0
    total = owner.data.get("total_earn") or 0

    supabase.table("users").update({
        "saldo": saldo + reward,
        "total_earn": total + reward
    }).eq("id", owner_id).execute()

    # =========================
    # KOMISI REFERRAL (10%)
    # =========================

    commission = int(reward * 0.10)

    ref = (
        supabase.table("referrals")
        .select("user_id")
        .eq("referred_user_id", owner_id)
        .limit(1)
        .execute()
    )

    if ref.data:

        referrer_id = ref.data[0]["user_id"]

        referrer = (
            supabase.table("users")
            .select("saldo")
            .eq("id", referrer_id)
            .single()
            .execute()
        )

        if referrer.data:

            ref_saldo = referrer.data.get("saldo") or 0

            supabase.table("users").update({
                "saldo": ref_saldo + commission
            }).eq("id", referrer_id).execute()

    # =========================
    # TOKEN SELESAI
    # =========================

    supabase.table("download_tokens").update({
        "used": True
    }).eq("token", token).execute()

    return RedirectResponse("/", status_code=303)
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
