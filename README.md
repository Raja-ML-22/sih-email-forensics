# AI Email Threat Detection & Forensic Intelligence Platform
SIH 2026 — PS ID 26106 — Team Tech Titans

## What's in this rebuild
Every file was regenerated from scratch in one consistent pass to fix
accumulated issues from incremental patching:
- **Fixed root cause of the Render crash**: the ML classifier could return
  `None` on model-load failure, which crashed the template (`None * 100`).
  It now always returns a valid float, plus an `available` flag, and the
  UI shows a graceful "unavailable" message instead of crashing.
- **Fixed the scikit-learn version mismatch**: `requirements.txt` now pins
  `scikit-learn==1.8.0`, the exact version the model was trained with.
- **`requirements.txt` is present and complete** — this was accidentally
  deleted from the GitHub repo before, which is why the Render build failed
  ("Exited with status 1"). Do not delete this file.

## Files
- `email_forensics.py` — core pipeline (parsing, SPF/DKIM/DMARC, IP/geo
  tracing, domain intel, ML + rule-based scoring, campaign correlation)
- `ml_classifier.py` — loads the trained model, never crashes the caller
- `neo4j_graph.py` — real Neo4j correlation with automatic JSON fallback
- `pdf_report.py` — downloadable forensic PDF report
- `app.py` — Flask web dashboard
- `train_classifier.py` — retrains the ML model from scratch if needed
- `phishing_classifier.joblib`, `tfidf_vectorizer.joblib`, `model_metadata.txt`
  — the trained model artifacts (Logistic Regression, 98.87% accuracy,
  trained on the Enron Spam Dataset)
- `requirements.txt` — pinned dependencies

## Local setup (Windows/Anaconda)
```
C:\Users\pesak\anaconda3\python.exe -m pip install -r requirements.txt
```

Set Neo4j credentials (only needed once per machine):
```
setx NEO4J_URI "neo4j+s://YOUR-INSTANCE.databases.neo4j.io"
setx NEO4J_USER "YOUR-USERNAME"
setx NEO4J_PASSWORD "YOUR-PASSWORD"
```
**Close and fully reopen VS Code** after running `setx` — it only affects
new terminal sessions, and VS Code needs a full restart to pick it up.

Verify before running the app:
```
C:\Users\pesak\anaconda3\python.exe -c "import neo4j_graph; print(neo4j_graph.is_neo4j_active())"
```

Run the app:
```
C:\Users\pesak\anaconda3\python.exe app.py
```

**Note on college WiFi:** Neo4j Aura connects over port 7687, which some
institutional networks block even though normal web traffic works fine.
If `is_neo4j_active()` prints `False` only on college WiFi but `True` on
mobile hotspot, that's a network port block, not a code problem — the app
automatically falls back to the local JSON store either way, so it keeps
working regardless.

## Deploying to Render
1. Push **all** files in this folder to your GitHub repo, including
   `requirements.txt` and the two `.joblib` model files.
2. On Render, set the same three Neo4j environment variables in the
   service's own **Environment** settings tab — variables set on your
   local machine do NOT carry over to Render, it's a separate machine.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`

## Retraining the ML model (optional)
Only needed if you want to retrain from scratch:
```
git clone --depth 1 https://github.com/MWiechmann/enron_spam_data.git
cd enron_spam_data && unzip enron_spam_data.zip && cd ..
python train_classifier.py
```
This regenerates `phishing_classifier.joblib`, `tfidf_vectorizer.joblib`,
and `model_metadata.txt`.
