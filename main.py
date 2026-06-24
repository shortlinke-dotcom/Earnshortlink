from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()

templates = Jinja2Templates(directory="templates")


# HOME
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )


# LOGIN PAGE
@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )


# REGISTER PAGE
@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html"
    )


# REGISTER PROCESS
@app.post("/register")
async def register_post(
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...)
):
    print("REGISTER:")
    print("Email:", email)
    print("Username:", username)

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )


# DASHBOARD
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html"
    )
