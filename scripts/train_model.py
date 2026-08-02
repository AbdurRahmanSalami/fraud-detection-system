from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline


RANDOM_STATE = 42

DATA_DIR = Path("data/raw")
MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def locate_dataset() -> Path:
    preferred_file = DATA_DIR / "Phishing_Email.csv"

    if preferred_file.exists():
        return preferred_file

    csv_files = list(DATA_DIR.glob("*.csv"))

    if len(csv_files) == 1:
        return csv_files[0]

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV file was found inside {DATA_DIR.resolve()}"
        )

    available_files = "\n".join(f"- {file.name}" for file in csv_files)

    raise RuntimeError(
        "More than one CSV file was found. Keep only the phishing-email "
        f"dataset in data/raw.\n{available_files}"
    )


def find_column(columns, possible_names):
    normalised = {
        str(column).strip().lower(): column
        for column in columns
    }

    for name in possible_names:
        if name.lower() in normalised:
            return normalised[name.lower()]

    return None


dataset_path = locate_dataset()

print(f"\nLoading dataset: {dataset_path}")
df = pd.read_csv(dataset_path, encoding_errors="replace")

print(f"Original rows: {len(df):,}")
print(f"Columns: {df.columns.tolist()}")

text_column = find_column(
    df.columns,
    [
        "Email Text",
        "email_text",
        "text",
        "message",
        "body",
        "email",
    ],
)

label_column = find_column(
    df.columns,
    [
        "Email Type",
        "email_type",
        "label",
        "type",
        "category",
        "class",
    ],
)

if text_column is None or label_column is None:
    raise ValueError(
        "Could not identify the text and label columns.\n"
        f"Available columns: {df.columns.tolist()}"
    )

print(f"Text column: {text_column}")
print(f"Label column: {label_column}")

data = df[[text_column, label_column]].copy()
data.columns = ["text", "original_label"]

data["text"] = data["text"].fillna("").astype(str).str.strip()
data["original_label"] = (
    data["original_label"]
    .fillna("")
    .astype(str)
    .str.strip()
)

data = data[
    (data["text"] != "")
    & (data["original_label"] != "")
].copy()

data["label"] = (
    data["original_label"]
    .str.lower()
    .str.contains("phishing")
    .astype(int)
)

data = data.drop_duplicates(subset=["text"]).reset_index(drop=True)

print(f"\nClean rows: {len(data):,}")
print("\nClass distribution:")
print(
    data["label"]
    .value_counts()
    .rename(index={0: "Safe Email", 1: "Phishing Email"})
)

X = data["text"]
y = data["label"]

# 70% training, 15% validation and 15% testing
X_train, X_temp, y_train, y_temp = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=RANDOM_STATE,
    stratify=y,
)

X_validation, X_test, y_validation, y_test = train_test_split(
    X_temp,
    y_temp,
    test_size=0.50,
    random_state=RANDOM_STATE,
    stratify=y_temp,
)

print("\nDataset split:")
print(f"Training:   {len(X_train):,}")
print(f"Validation: {len(X_validation):,}")
print(f"Testing:    {len(X_test):,}")

pipeline = Pipeline(
    [
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                stop_words="english",
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.95,
                max_features=100_000,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            MultinomialNB(alpha=0.5),
        ),
    ]
)

print("\nTraining model...")
pipeline.fit(X_train, y_train)

validation_probabilities = pipeline.predict_proba(X_validation)[:, 1]

thresholds = np.arange(0.10, 0.91, 0.01)

best_threshold = 0.50
best_validation_f1 = -1.0

for threshold in thresholds:
    predictions = (
        validation_probabilities >= threshold
    ).astype(int)

    score = f1_score(
        y_validation,
        predictions,
        average="macro",
    )

    if score > best_validation_f1:
        best_validation_f1 = score
        best_threshold = float(round(threshold, 2))

print(f"Best threshold: {best_threshold:.2f}")
print(f"Validation macro F1: {best_validation_f1:.4f}")

test_probabilities = pipeline.predict_proba(X_test)[:, 1]
test_predictions = (
    test_probabilities >= best_threshold
).astype(int)

accuracy = accuracy_score(y_test, test_predictions)
precision = precision_score(
    y_test,
    test_predictions,
    zero_division=0,
)
recall = recall_score(
    y_test,
    test_predictions,
    zero_division=0,
)
f1 = f1_score(
    y_test,
    test_predictions,
    zero_division=0,
)
macro_f1 = f1_score(
    y_test,
    test_predictions,
    average="macro",
)
roc_auc = roc_auc_score(y_test, test_probabilities)
matrix = confusion_matrix(y_test, test_predictions)

print("\nTEST RESULTS")
print("=" * 45)
print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 score:  {f1:.4f}")
print(f"Macro F1:  {macro_f1:.4f}")
print(f"ROC AUC:   {roc_auc:.4f}")

print("\nConfusion matrix:")
print(matrix)

print("\nClassification report:")
print(
    classification_report(
        y_test,
        test_predictions,
        target_names=["Safe Email", "Phishing Email"],
        zero_division=0,
    )
)

model_artifact = {
    "pipeline": pipeline,
    "threshold": best_threshold,
    "labels": {
        0: "Safe Email",
        1: "Phishing Email",
    },
}

model_path = MODEL_DIR / "phishing_nb.joblib"
joblib.dump(model_artifact, model_path)

metrics = {
    "dataset": dataset_path.name,
    "total_clean_rows": int(len(data)),
    "training_rows": int(len(X_train)),
    "validation_rows": int(len(X_validation)),
    "testing_rows": int(len(X_test)),
    "best_threshold": best_threshold,
    "validation_macro_f1": float(best_validation_f1),
    "test_accuracy": float(accuracy),
    "test_precision": float(precision),
    "test_recall": float(recall),
    "test_f1": float(f1),
    "test_macro_f1": float(macro_f1),
    "test_roc_auc": float(roc_auc),
    "confusion_matrix": matrix.tolist(),
}

metrics_path = REPORT_DIR / "metrics.json"

with metrics_path.open("w", encoding="utf-8") as file:
    json.dump(metrics, file, indent=4)

clean_data_path = Path("data/processed/emails_clean.csv")
clean_data_path.parent.mkdir(parents=True, exist_ok=True)
data[["text", "label"]].to_csv(clean_data_path, index=False)

print("\nFiles saved successfully:")
print(f"- Model: {model_path}")
print(f"- Metrics: {metrics_path}")
print(f"- Clean dataset: {clean_data_path}")
