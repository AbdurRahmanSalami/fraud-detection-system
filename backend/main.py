import os
from pathlib import Path

import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "models" / "phishing_nb.joblib"


if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Trained model not found at: {MODEL_PATH}"
    )


model_artifact = joblib.load(MODEL_PATH)

pipeline = model_artifact["pipeline"]
threshold = float(model_artifact["threshold"])
labels = model_artifact["labels"]

frontend_url = os.getenv("FRONTEND_URL", "").rstrip("/")

allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

if frontend_url:
    allowed_origins.append(frontend_url)

app = FastAPI(
    title="Phishing Email Detection API",
    description="Detects potentially fraudulent or phishing email messages.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailInput(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="The email content to analyse.",
    )


def determine_risk_level(probability: float) -> str:
    if probability >= 0.80:
        return "High"
    if probability >= 0.50:
        return "Medium"
    return "Low"


@app.get("/")
def home():
    return {
        "message": "Phishing Email Detection API is running",
        "model_loaded": True,
        "threshold": threshold,
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": True,
    }


@app.post("/predict")
def predict_email(payload: EmailInput):
    cleaned_text = payload.text.strip()

    if not cleaned_text:
        raise HTTPException(
            status_code=400,
            detail="Email text cannot be empty.",
        )

    probabilities = pipeline.predict_proba([cleaned_text])[0]

    safe_probability = float(probabilities[0])
    phishing_probability = float(probabilities[1])

    predicted_class = int(
        phishing_probability >= threshold
    )

    return {
        "label": labels[predicted_class],
        "is_phishing": bool(predicted_class),
        "phishing_probability": round(
            phishing_probability,
            4,
        ),
        "safe_probability": round(
            safe_probability,
            4,
        ),
        "confidence_percentage": round(
            max(safe_probability, phishing_probability) * 100,
            2,
        ),
        "risk_level": determine_risk_level(
            phishing_probability
        ),
        "classification_threshold": threshold,
        "characters_analysed": len(cleaned_text),
    }
