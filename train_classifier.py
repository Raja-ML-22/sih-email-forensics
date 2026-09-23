"""
Trains a real ML classifier for phishing/fraud email text detection —
replacing the keyword-rule text signal in the SIH prototype with an
actually-trained model, per the PS requirement:
"AI/ML models to classify emails as legitimate, suspicious, impersonated,
phishing, or fraud-related."

Dataset: Enron Spam Dataset (33,716 labeled emails, real, publicly cited
in our References slide) — github.com/MWiechmann/enron_spam_data
"""

import pandas as pd
import numpy as np
import joblib
import time
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from xgboost import XGBClassifier

print("Loading dataset...")
df = pd.read_csv("enron_spam_data/enron_spam_data.csv")
df["Subject"] = df["Subject"].fillna("")
df["Message"] = df["Message"].fillna("")
df["text"] = (df["Subject"] + " " + df["Message"]).str.strip()
df = df[df["text"].str.len() > 0].reset_index(drop=True)
df["label"] = (df["Spam/Ham"] == "spam").astype(int)

print(f"Total usable rows: {len(df)}")
print(df["label"].value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
)
print(f"Train: {len(X_train)}, Test: {len(X_test)}")

print("\nVectorizing (TF-IDF, 5000 features)...")
vectorizer = TfidfVectorizer(
    max_features=5000, stop_words="english", ngram_range=(1, 2), min_df=2
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

results = {}

def evaluate(name, model, X_tr, X_te):
    start = time.time()
    model.fit(X_tr, y_train)
    train_time = time.time() - start
    preds = model.predict(X_te)
    probs = model.predict_proba(X_te)[:, 1]
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    results[name] = {
        "model": model, "accuracy": acc, "precision": prec,
        "recall": rec, "f1": f1, "roc_auc": auc, "train_time": train_time
    }
    print(f"\n{name} (trained in {train_time:.1f}s)")
    print(f"  Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f} | ROC-AUC: {auc:.4f}")
    print(f"  Confusion matrix:\n{confusion_matrix(y_test, preds)}")

print("\n" + "="*60)
print("Training and evaluating 3 models...")
print("="*60)

evaluate("Logistic Regression", LogisticRegression(max_iter=1000, C=1.0), X_train_vec, X_test_vec)
evaluate("Random Forest", RandomForestClassifier(n_estimators=200, max_depth=30, n_jobs=-1, random_state=42), X_train_vec, X_test_vec)
evaluate("XGBoost", XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=42), X_train_vec, X_test_vec)

print("\n" + "="*60)
best_name = max(results, key=lambda k: results[k]["f1"])
print(f"Best model by F1 score: {best_name}")
print("="*60)
best = results[best_name]
for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
    print(f"  {k}: {best[k]:.4f}")

# Save the best model + vectorizer for integration into the prototype
joblib.dump(best["model"], "phishing_classifier.joblib")
joblib.dump(vectorizer, "tfidf_vectorizer.joblib")
with open("model_metadata.txt", "w") as f:
    f.write(f"Model: {best_name}\n")
    f.write(f"Trained on: Enron Spam Dataset (33,716 emails, github.com/MWiechmann/enron_spam_data)\n")
    f.write(f"Train/test split: 80/20 stratified, random_state=42\n")
    f.write(f"Accuracy: {best['accuracy']:.4f}\n")
    f.write(f"Precision: {best['precision']:.4f}\n")
    f.write(f"Recall: {best['recall']:.4f}\n")
    f.write(f"F1: {best['f1']:.4f}\n")
    f.write(f"ROC-AUC: {best['roc_auc']:.4f}\n")

print("\nSaved: phishing_classifier.joblib, tfidf_vectorizer.joblib, model_metadata.txt")
