# FraudGuard AI

FraudGuard AI is a machine-learning web application that detects phishing emails from their textual content.

The system uses TF-IDF feature extraction and a Multinomial Naïve Bayes classifier. It provides a prediction, phishing probability, safe-email probability, confidence score and risk level through a React dashboard.

## Live Demo

https://fraudguard-ai-phi.vercel.app

## Model Performance

| Metric | Result |
|---|---:|
| Accuracy | 98.52% |
| Precision | 97.97% |
| Recall | 98.07% |
| F1 Score | 98.02% |
| Macro F1 | 98.42% |
| ROC AUC | 99.76% |

### Confusion Matrix

- Correctly classified safe emails: 1,627
- Correctly classified phishing emails: 963
- Safe emails incorrectly flagged: 20
- Phishing emails missed: 19

## Technologies

### Machine Learning

- Python
- pandas
- scikit-learn
- TF-IDF
- Multinomial Naïve Bayes
- joblib

### Backend

- FastAPI
- Pydantic
- Uvicorn

### Frontend

- React
- Vite
- Axios
- Lucide React

## Project Structure

```text
fraud-detection-system/
├── backend/
│   └── main.py
├── data/
│   ├── raw/
│   └── processed/
├── frontend/
├── models/
│   └── phishing_nb.joblib
├── reports/
│   └── metrics.json
├── scripts/
│   └── train_model.py
├── requirements.txt
└── README.md
