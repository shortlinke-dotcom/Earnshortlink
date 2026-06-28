import os
import random
import string
import secrets
import calendar
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Form, Body
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response
)
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from auth import hash_password, verify_password
from database import supabase


# =========================
# APP INIT (ONLY ONCE)
# =========================
app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET")
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
    request.session["user_id"] = user["id"]

    return RedirectResponse("/dashboard", 303)


# =========================
# GOOGLE LOGIN (START)
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
async def google_session(request: Request):
    data = await request.json()

    email = data.get("email")

    if not email:
        return JSONResponse({"ok": False, "error": "no_email"}, status_code=400)

    # cek user di DB
    user_res = (
        supabase.table("users")
        .select("*")
        .eq("gmail", email)
        .limit(1)
        .execute()
    )

    # =========================
    # USER SUDAH ADA → LOGIN
    # =========================
    if user_res.data:
        user = user_res.data[0]

        if user.get("is_banned"):
            return JSONResponse({"ok": False, "error": "banned"}, status_code=403)

        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]

        return JSONResponse({"ok": True})

    # =========================
    # USER BARU → SETUP USERNAME
    # =========================
    request.session["pending_email"] = email

    return JSONResponse({
        "ok": True,
        "new_user": True
    })
    
# =========================
# GOOGLE CALLBACK (FINAL)
# =========================
@app.get("/auth/callback")
async def auth_callback(request: Request, code: str | None = None, error: str | None = None):

    # =========================
    # HANDLE ERROR
    # =========================
    if error:
        return RedirectResponse("/login?error=google_failed")

    if not code:
        return RedirectResponse("/login?error=google_failed")

    try:
        # tukar code → session supabase
        session = supabase.auth.exchange_code_for_session(code)

        if not session or not session.user:
            return RedirectResponse("/login?error=google_failed")

        email = session.user.email

    except Exception as e:
        print("OAuth callback error:", e)
        return RedirectResponse("/login?error=google_failed")

    # =========================
    # CEK USER DI DATABASE
    # =========================
    result = (
        supabase.table("users")
        .select("*")
        .eq("gmail", email)
        .limit(1)
        .execute()
    )

    # =========================
    # USER BELUM ADA
    # =========================
    if not result.data:
        request.session["pending_email"] = email
        return RedirectResponse("/setup-username")

    user = result.data[0]

    # =========================
    # CEK BANNED
    # =========================
    if user.get("is_banned"):
        return RedirectResponse("/login?error=banned")

    # =========================
    # SET SESSION (PENTING)
    # =========================
    request.session["username"] = user.get("username")
    request.session["user_id"] = user.get("id")
    request.session["logged_in"] = True

    # =========================
    # REDIRECT DASHBOARD
    # =========================
    return RedirectResponse("/dashboard")
    
# =========================
# SETUP USERNAME (GET)
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


# =========================
# SETUP USERNAME (POST)
# =========================
@app.post("/setup-username")
async def setup_username_post(request: Request, username: str = Form(...)):

    email = request.session.get("pending_email")

    if not email:
        return RedirectResponse("/login", 303)

    username = username.strip().lower()

    # =========================
    # VALIDASI
    # =========================
    if len(username) < 3:
        return RedirectResponse("/setup-username?error=short", 303)

    if " " in username:
        return RedirectResponse("/setup-username?error=space", 303)

    # =========================
    # CEK USERNAME
    # =========================
    check = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .limit(1)
        .execute()
    )

    if check.data:
        return RedirectResponse("/setup-username?error=exists", 303)

    # =========================
    # INSERT USER (AMBIL DATA BALIK)
    # =========================
    insert = (
        supabase.table("users")
        .insert({
            "gmail": email,
            "username": username,
            "password": "",
        })
        .execute()
    )

    if not insert.data:
        return RedirectResponse("/setup-username?error=failed", 303)

    new_user = insert.data[0]

    # =========================
    # SET SESSION (PENTING)
    # =========================
    request.session["username"] = new_user.get("username")
    request.session["user_id"] = new_user.get("id")
    request.session["logged_in"] = True

    # hapus pending email
    request.session.pop("pending_email", None)

    return RedirectResponse("/dashboard", 303)


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

# =========================
# DASHBOARD
# =========================
@app.get("/dashboard")
async def dashboard(request: Request):

    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    # ================= USER =================
    result = (
        supabase.table("users")
        .select("*")
        .eq("id", user_id)
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

    # ================= LINKS =================
    links_res = (
        supabase.table("links")
        .select("id, clicks, earnings, created_at")
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
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
        except:
            return None

    # ================= HITUNG =================
    total_clicks = 0
    total_earnings = 0

    for link in links:
        clicks = link.get("clicks") or 0
        earnings = link.get("earnings") or 0
        created = parse_date(link.get("created_at"))

        total_clicks += clicks
        total_earnings += earnings

        if created:
            if created.date() == today:
                today_clicks += clicks
                today_earnings += earnings

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
        r["referred_user_id"]
        for r in (ref_res.data or [])
        if r.get("referred_user_id")
    ]

    active_referrals = 0

    if referred_ids:
        users_res = (
            supabase.table("users")
            .select("id, clicks")
            .in_("id", referred_ids)
            .execute()
        )

        active_referrals = sum(
            1 for u in (users_res.data or [])
            if (u.get("clicks") or 0) > 0
        )

    # ================= REFERRAL EARNINGS =================
    referral_earnings = user.get("referral_earnings") or 0

    # ❌ HAPUS INI (gak perlu update tiap load)
    # supabase.table("users").update(...)

    # ================= CPM =================
    average_cpm = round(today_earnings / today_clicks, 2) if today_clicks else 0
    month_cpm = round(month_earnings / month_clicks, 2) if month_clicks else 0

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

        chart_labels.append(
            created.strftime("%d/%m") if created else "-"
        )

        chart_clicks.append(link.get("clicks") or 0)
        chart_earnings.append(link.get("earnings") or 0)

    # ================= RENDER =================
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "username": user.get("username"),
            "saldo": user.get("saldo") or 0,

            "total_links": total_links,
            "total_clicks": total_clicks,
            "total_earnings": total_earnings,

            "today": today.strftime("%d %B %Y"),
            "today_clicks": today_clicks,
            "today_earnings": today_earnings,

            "month_clicks": month_clicks,
            "month_earnings": month_earnings,

            "average_cpm": average_cpm,
            "month_cpm": month_cpm,

            "chart_labels": chart_labels,
            "chart_clicks": chart_clicks,
            "chart_earnings": chart_earnings,

            "latest_links": links[:5],
            "links": links,

            "active_referrals": active_referrals,
            "referral_earnings": referral_earnings,
            "referral_code": user.get("username"),

            "current_month_name": calendar.month_name[current_month],
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

    username = request.session.get("username")
    if not username:
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    user_res = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .single()
        .execute()
    )

    if not user_res.data:
        return JSONResponse({"ok": False, "error": "user_not_found"}, status_code=404)

    user_id = user_res.data["id"]

    code = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    supabase.table("sell_links").insert({
        "user_id": user_id,
        "code": code,
        "title": title,
        "destination_url": destination_url,
        "price": int(price),
        "sold": 0,
        "income": 0
    }).execute()

    return JSONResponse({
        "ok": True,
        "link": f"{request.base_url}pay/{code}"
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
        "income": 0
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

    username = request.session.get("username")
    if not username:
        return JSONResponse({"ok": False}, status_code=401)

    user_res = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .single()
        .execute()
    )

    if not user_res.data:
        return JSONResponse({"ok": False}, status_code=404)

    user_id = user_res.data["id"]

    supabase.table("sell_links") \
        .delete() \
        .eq("code", code) \
        .eq("user_id", user_id) \
        .execute()

    return {"ok": True}


# =========================
# EDIT SELL LINK
# =========================
@app.post("/edit-sell-link")
async def edit_sell_link(request: Request, data: dict = Body(...)):

    username = request.session.get("username")
    if not username:
        return JSONResponse({"ok": False}, status_code=401)

    code = data.get("code")
    title = data.get("title")
    price = data.get("price")

    supabase.table("sell_links").update({
        "title": title,
        "price": int(price)
    }).eq("code", code).execute()

    return {"ok": True}
# =========================
# CREATE SHORT LINK
# =========================
@app.post("/create-link")
async def create_link(
    request: Request,
    destination_url: str = Form(...),
    title: str = Form(...)
):

    # =========================
    # LOGIN CHECK
    # =========================
    username = request.session.get("username")

    if not username:
        return JSONResponse(
            {"ok": False, "error": "Unauthorized"},
            status_code=401
        )

    # =========================
    # GET USER
    # =========================
    user_res = (
        supabase.table("users")
        .select("id")
        .eq("username", username)
        .single()
        .execute()
    )

    if not user_res.data:
        return JSONResponse(
            {"ok": False, "error": "User not found"},
            status_code=404
        )

    user_id = user_res.data["id"]

    # =========================
    # VALIDASI URL
    # =========================
    destination_url = destination_url.strip()

    if not (
        destination_url.startswith("http://")
        or destination_url.startswith("https://")
    ):
        destination_url = "https://" + destination_url

    # =========================
    # GENERATE SHORT CODE
    # =========================
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

    # =========================
    # INSERT DATABASE
    # =========================
    insert = (
        supabase.table("links")
        .insert({
            "user_id": user_id,
            "title": title.strip(),
            "destination_url": destination_url,
            "short_code": short_code,
            "clicks": 0,
            "earnings": 0,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        .execute()
    )

    if not insert.data:
        return JSONResponse(
            {
                "ok": False,
                "error": "Failed create link"
            },
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

@app.post("/logout-all")
async def logout_all(request: Request):
    request.session.clear()
    return RedirectResponse("/login", 303)

@app.post("/delete-account")
async def delete_account(request: Request):
    user_id = request.session.get("user_id")

    supabase.table("users")\
        .delete()\
        .eq("id", user_id)\
        .execute()

    request.session.clear()
    return RedirectResponse("/", 303)


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
