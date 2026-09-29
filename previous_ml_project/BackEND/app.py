from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from pydantic import BaseModel
import joblib

from db_mysql import add_report
from db_user import create_user, get_user

app = FastAPI(title="ClickSafe Scam Link Detector API")

# Correct CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = "model/model.joblib"

try:
    pipeline = joblib.load(MODEL_PATH)
    print("Model loaded successfully")
except Exception as e:
    pipeline = None
    print("Model not found:", e)


class PredictRequest(BaseModel):
    url: str

class PredictResponse(BaseModel):
    url: str
    label: str
    confidence: float
    rules: list
    explanation: list

class ReportRequest(BaseModel):
    url: str
    reporter: str
    notes: str | None = None

class ReportResponse(BaseModel):
    ok: bool
    id: int

class SignupRequest(BaseModel):
    name: str
    mobile: str

class LoginRequest(BaseModel):
    mobile: str


def apply_rules(url: str):
    rules = []
    explanation = []

    if url.startswith("http://"):
        rules.append("no https")
        explanation.append("URL does not use https")

    return rules, explanation


@app.post("/predict")
def predict(request: PredictRequest):
    if pipeline is None:
        raise HTTPException(status_code=500, detail="Model not loaded")

    url = request.url.strip()

    raw_label = pipeline.predict([url])[0]
    proba = pipeline.predict_proba([url])[0]
    confidence = float(max(proba))

    label = "safe" if raw_label == "good" else "scam"

    rules, explanation = apply_rules(url)

    return PredictResponse(
        url=url,
        label=label,
        confidence=confidence,
        rules=rules,
        explanation=explanation
    )


@app.post("/report")
def report(request: ReportRequest):
    rep_id = add_report(request.url, request.reporter, request.notes)
    return ReportResponse(ok=True, id=rep_id)


@app.post("/signup")
def signup(request: SignupRequest):
    user = get_user(request.mobile)
    if user:
        raise HTTPException(status_code=400, detail="User already exists")

    new_id = create_user(request.name, request.mobile)
    return {"ok": True, "user_id": new_id}


@app.post("/login")
def login(request: LoginRequest):
    user = get_user(request.mobile)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "ok": True,
        "user": {
            "id": user[0],
            "name": user[1],
            "mobile": user[2]
        }
    }


@app.get("/")
def home():
    return {"message": "ClickSafe backend running"}


@app.on_event("startup")
def show_routes():
    print("Registered Routes:")
    for route in app.routes:
        if isinstance(route, APIRoute):
            print(route.path, route.methods)
