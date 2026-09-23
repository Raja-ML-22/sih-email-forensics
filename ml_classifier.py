"""
ML Classifier Integration Module — SIH 2026, PS ID 26106, Team Tech Titans

Loads the trained phishing/spam text classifier (Logistic Regression,
trained on the Enron Spam Dataset — see train_classifier.py and
model_metadata.txt for full training details and metrics) and exposes a
simple predict function for use in the main forensics pipeline.

This REPLACES the old keyword-list urgency check with a genuinely trained
ML model, directly answering the PS requirement:
"AI/ML models to classify emails as legitimate, suspicious, impersonated,
phishing, or fraud-related."
"""

import os
import joblib

_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
_model = None
_vectorizer = None


def _load():
    global _model, _vectorizer
    if _model is None:
        _model = joblib.load(os.path.join(_MODEL_DIR, "phishing_classifier.joblib"))
        _vectorizer = joblib.load(os.path.join(_MODEL_DIR, "tfidf_vectorizer.joblib"))
    return _model, _vectorizer


def predict_phishing_probability(subject, body):
    """
    Returns (probability, label) where probability is the model's confidence
    (0.0-1.0) that the email is spam/phishing, and label is "phishing" or "legitimate".
    """
    model, vectorizer = _load()
    text = f"{subject or ''} {body or ''}".strip()
    if not text:
        return 0.0, "legitimate"
    X = vectorizer.transform([text])
    prob = model.predict_proba(X)[0][1]
    label = "phishing" if prob >= 0.5 else "legitimate"
    return float(prob), label


def get_model_info():
    return {
        "model_type": "Logistic Regression (TF-IDF, 5000 features, unigram+bigram)",
        "trained_on": "Enron Spam Dataset, 33,665 labeled emails",
        "source": "github.com/MWiechmann/enron_spam_data",
        "metrics": {
            "accuracy": 0.9887,
            "precision": 0.9847,
            "recall": 0.9933,
            "f1": 0.9890,
            "roc_auc": 0.9988,
        },
    }


if __name__ == "__main__":
    # quick self-test
    prob, label = predict_phishing_probability(
        "URGENT: Invoice Payment Overdue",
        "This is an urgent notice. Please click here to confirm your password and complete the wire transfer."
    )
    print(f"Phishing sample -> probability={prob:.4f}, label={label}")

    prob2, label2 = predict_phishing_probability(
        "Team meeting notes",
        "Hi team, attached are the notes from today's project sync. Let me know if I missed anything."
    )
    print(f"Clean sample -> probability={prob2:.4f}, label={label2}")
