"""
Trains the phishing/spam text classifier for the SIH 2026 email forensics
platform — PS ID 26106, Team Tech Titans.

Dataset: Enron Spam Dataset (github.com/MWiechmann/enron_spam_data)
"""

import pandas as pd
import time
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from xgboost import XGBClassifier

print("Loading dataset...")
df = pd.read_csv("enron_spam_data/enron_spam_data.csv")
df["Subject"] = df["Subject"].fillna("")
df["Message"] = df["Message"].fillna("")
df["text"] = (df["Subject"] + " " + df["Message"]).str.strip()
df = df[df["text"].str.len() > 0].reset_index(drop=True)
df["label"] = (df["Spam/Ham"] == "spam").astype(int)
print(f"Rows: {len(df)} | Class balance:\n{df['label'].value_counts()}")

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
)

vectorizer = TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2), min_df=2)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

results = {}

def evaluate(name, model):
    t0 = time.time()
    model.fit(X_train_vec, y_train)
    preds = model.predict(X_test_vec)
    probs = model.predict_proba(X_test_vec)[:, 1]
    results[name] = {
        "model": model,
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds),
        "recall": recall_score(y_test, preds),
        "f1": f1_score(y_test, preds),
        "roc_auc": roc_auc_score(y_test, probs),
    }
    print(f"\n{name} ({time.time()-t0:.1f}s)")
    for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
        print(f"  {k}: {results[name][k]:.4f}")
    print(f"  Confusion matrix:\n{confusion_matrix(y_test, preds)}")

evaluate("Logistic Regression", LogisticRegression(max_iter=1000, C=1.0))
evaluate("Random Forest", RandomForestClassifier(n_estimators=200, max_depth=30, n_jobs=-1, random_state=42))
evaluate("XGBoost", XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=42))

best_name = max(results, key=lambda k: results[k]["f1"])
best = results[best_name]
print(f"\nBest model: {best_name}")

joblib.dump(best["model"], "phishing_classifier.joblib")
joblib.dump(vectorizer, "tfidf_vectorizer.joblib")
with open("model_metadata.txt", "w") as f:
    f.write(f"Model: {best_name}\n")
    f.write("Trained on: Enron Spam Dataset (33,665 usable emails, github.com/MWiechmann/enron_spam_data)\n")
    f.write("Train/test split: 80/20 stratified, random_state=42\n")
    for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
        f.write(f"{k}: {best[k]:.4f}\n")
    import sklearn
    f.write(f"scikit-learn version used to train: {sklearn.__version__}\n")

print("\nSaved: phishing_classifier.joblib, tfidf_vectorizer.joblib, model_metadata.txt")
