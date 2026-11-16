# train_model.py

import os
import re
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "dataset", "prompts.csv")
CUSTOM_PATH = os.path.join(BASE_DIR, "dataset", "custom_prompts.csv")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "threat_model.joblib")

# Your own examples are few, so repeat them to give them more weight.
CUSTOM_REPEAT = 5


def find_column(columns, possible_names):
    """Find a column using common column names."""
    for column in columns:
        cleaned = re.sub(r"[^a-z0-9]", "", str(column).lower())

        if cleaned in possible_names:
            return column

    return None


def convert_label(value):
    """Convert common safe/malicious labels to 0 or 1."""
    if pd.isna(value):
        return None

    text = str(value).strip().lower()

    malicious_labels = {
        "1", "1.0", "true", "yes", "malicious", "unsafe",
        "attack", "injection", "prompt injection", "harmful"
    }

    benign_labels = {
        "0", "0.0", "false", "no", "benign", "safe",
        "normal", "legitimate", "clean"
    }

    if text in malicious_labels:
        return 1

    if text in benign_labels:
        return 0

    return None


def clean(data):
    """Keep only valid text and 0/1 labels."""
    data = data.copy()
    data["text"] = data["text"].fillna("").astype(str).str.strip()
    data["label"] = data["label"].apply(convert_label)
    data = data.dropna(subset=["label"])
    data = data[data["text"] != ""]
    data["label"] = data["label"].astype(int)
    return data


def load_big_dataset():
    """Load dataset/prompts.csv if it exists and has content."""
    if not os.path.exists(DATA_PATH) or os.path.getsize(DATA_PATH) == 0:
        print("prompts.csv is missing or empty, so it was skipped.")
        return None

    try:
        big = pd.read_csv(DATA_PATH)
    except Exception as error:
        print("prompts.csv skipped:", error)
        return None

    text_column = find_column(
        big.columns,
        {"prompt", "text", "input", "userprompt",
         "content", "sentence", "query"}
    )
    label_column = find_column(
        big.columns,
        {"label", "class", "target", "category",
         "ismalicious", "malicious", "isattack"}
    )

    if text_column is None or label_column is None:
        print("prompts.csv skipped: columns not recognised:",
              list(big.columns))
        return None

    big = big[[text_column, label_column]].copy()
    big.columns = ["text", "label"]
    big = clean(big)
    print("prompts.csv rows used:", len(big))
    return big


def load_custom_dataset():
    """Load dataset/custom_prompts.csv (columns: text,label)."""
    if not os.path.exists(CUSTOM_PATH) or os.path.getsize(CUSTOM_PATH) == 0:
        print(f"Custom file missing or empty: {CUSTOM_PATH}")
        return None

    try:
        custom = pd.read_csv(CUSTOM_PATH, encoding="utf-8-sig")
        custom = custom[["text", "label"]].copy()
    except Exception as error:
        print("custom_prompts.csv skipped:", error)
        print("Check that the first line is exactly: text,label")
        return None

    custom = clean(custom)

    if custom.empty:
        print("custom_prompts.csv has no valid rows.")
        return None

    print("Custom examples added:", len(custom),
          f"(each repeated {CUSTOM_REPEAT} times)")
    return pd.concat([custom] * CUSTOM_REPEAT, ignore_index=True)


def main():
    frames = []

    big = load_big_dataset()
    if big is not None and not big.empty:
        frames.append(big)

    custom = load_custom_dataset()
    if custom is not None and not custom.empty:
        frames.append(custom)

    if not frames:
        print("No training data found. Fill dataset/custom_prompts.csv first.")
        return

    data = pd.concat(frames, ignore_index=True)

    if data["label"].nunique() != 2:
        print("The dataset must contain both safe and malicious examples.")
        print("Recognized labels:", data["label"].value_counts().to_dict())
        return

    if data["label"].value_counts().min() < 2:
        print("You need at least two examples of each class.")
        return

    print("Total training rows:", len(data))
    print("Label counts (0 = safe, 1 = malicious):",
          data["label"].value_counts().to_dict())

    X = data["text"]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                max_features=30000
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced"
            )
        )
    ])

    print("\nTraining the classifier...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    # Save to a temporary file first, then swap it in, so a running
    # server never reads a half-written model file.
    os.makedirs(MODEL_DIR, exist_ok=True)
    temp_path = MODEL_PATH + ".tmp"
    joblib.dump(model, temp_path)
    os.replace(temp_path, MODEL_PATH)

    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()