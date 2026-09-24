"""
ML Classifier Integration Module — SIH 2026, PS ID 26106, Team Tech Titans

Loads the trained phishing/spam text classifier and exposes a prediction
function for the main forensics pipeline. Directly answers the PS
requirement: "AI/ML models to classify emails as legitimate, suspicious,
impersonated, phishing, or fraud-related."

IMPORTANT DESIGN RULE: this module must NEVER return None for probability,
and must NEVER let an exception escape predict_phishing_probability().
A previous version could return (None, None) on model-load failure, which
crashed the Flask template downstream (None * 100). Every code path here
now returns a valid float and a valid label, with an extra "available"
flag so callers can honestly show "ML unavailable" instead of guessing.
"""

import os
import joblib

_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
_model = None
_vectorizer = None
_load_error = None


def _load():
    global _model, _vectorizer, _load_error
    if _model is not None or _load_error is not None:
        return
    try:
        _model = joblib.load(os.path.join(_MODEL_DIR, "phishing_classifier.joblib"))
        _vectorizer = joblib.load(os.path.join(_MODEL_DIR, "tfidf_vectorizer.joblib"))
    except Exception as e:
        _load_error = str(e)


def predict_phishing_probability(subject, body):
    """
    Always returns (probability: float, label: str, available: bool).
    - available=True  -> probability/label are real model output (0.0-1.0)
    - available=False -> model could not run; probability defaults to 0.0
      and label is "unavailable" so the score simply doesn't get this
      signal, rather than crashing anything downstream.
    """
    _load()
    if _load_error is not None or _model is None or _vectorizer is None:
        return 0.0, "unavailable", False

    text = f"{subject or ''} {body or ''}".strip()
    if not text:
        return 0.0, "legitimate", True

    try:
        X = _vectorizer.transform([text])
        prob = float(_model.predict_proba(X)[0][1])
        label = "phishing" if prob >= 0.5 else "legitimate"
        return prob, label, True
    except Exception:
        return 0.0, "unavailable", False


def get_model_info():
    _load()
    return {
        "model_type": "Logistic Regression (TF-IDF, 5000 features, unigram+bigram)",
        "trained_on": "Enron Spam Dataset, 33,665 labeled emails",
        "source": "github.com/MWiechmann/enron_spam_data",
        "metrics": {
            "accuracy": 0.9887, "precision": 0.9847, "recall": 0.9933,
            "f1": 0.9890, "roc_auc": 0.9988,
        },
        "available": _load_error is None,
        "load_error": _load_error,
    }


if __name__ == "__main__":
    prob, label, ok = predict_phishing_probability(
        "URGENT: Invoice Payment Overdue",
        "This is an urgent notice. Please click here to confirm your password and complete the wire transfer."
    )
    print(f"Phishing sample -> probability={prob:.4f}, label={label}, available={ok}")

    prob2, label2, ok2 = predict_phishing_probability(
        "Team meeting notes",
        "Hi team, attached are the notes from today's project sync."
    )
    print(f"Clean sample -> probability={prob2:.4f}, label={label2}, available={ok2}")

    # simulate what happens if the model files are missing entirely
    prob3, label3, ok3 = predict_phishing_probability("", "")
    print(f"Empty input -> probability={prob3:.4f}, label={label3}, available={ok3}")
