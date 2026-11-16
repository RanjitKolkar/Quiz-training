# DGIT Training MCQ Assessment (Streamlit)

## Features
- 20 moderate, scenario-based MCQs based on the DGIT Batch 4 training timetable (12–16 October 2026).
- Admin starts/restarts the assessment and sets the shared timer (default 10 minutes).
- Countdown is visible to trainees and automatically submits their current answers when time expires.
- Larger fonts, wider layout and clearer question cards.
- Trainee must enter their full name; organisation/department is optional.
- Score and answers are **not shown to trainees** after submission.
- Admin-only results page with trainee name, organisation, timestamp, score and CSV export.
- Results can be stored in SQLite for local testing or Google Sheets for persistent Streamlit Cloud storage.

## Run locally
1. Install Python 3.10 or later.
2. Open a terminal in this folder.
3. Run:
   ```bash
   pip install -r requirements.txt
   streamlit run app.py
   ```
4. Open the local URL printed by Streamlit (usually http://localhost:8501).

## Deploy on GitHub + Streamlit Community Cloud
1. Create a GitHub repository and upload `app.py`, `requirements.txt`, and this README.
2. In Streamlit Community Cloud, create an app from that repository and select `app.py`.
3. Open the app's **Settings → Secrets** and add the configuration below.

### Required admin password
Set the administrator password (currently configured as requested):
```toml
ADMIN_PASSWORD = "Nitk@12345"
```

### Recommended: persistent Google Sheets storage
SQLite is suitable for local testing, but files on Streamlit Community Cloud are not guaranteed to persist across restarts/redeployments. For durable hosted results, use a dedicated Google Sheet.

1. Create a Google Cloud service account and enable the Google Sheets API.
2. Create a Google Sheet for assessment results.
3. Share the Sheet with the service-account email address as **Editor**.
4. Copy the Sheet ID from its URL.
5. Add the following to Streamlit **Secrets** (replace the example values with the service account JSON values):
```toml
ADMIN_PASSWORD = "Nitk@12345"
GOOGLE_SHEET_ID = "your-google-sheet-id"

[gcp_service_account]
type = "service_account"
project_id = "your-project-id"
private_key_id = "your-private-key-id"
private_key = "-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----\n"
client_email = "your-service-account@your-project.iam.gserviceaccount.com"
client_id = "your-client-id"
token_uri = "https://oauth2.googleapis.com/token"
```
Use the complete service-account JSON fields supplied by Google. Keep these secrets in Streamlit's Secrets manager only. **Never commit credentials or private keys to GitHub.**

When Google Sheets secrets are configured, submissions are written to the Sheet and the Admin page reads results from that Sheet. If Google Sheets is not configured, the app uses local SQLite for testing.

## Important security notes
- This is a basic training assessment app, not a high-assurance examination platform.
- Admin password is checked server-side using Streamlit secrets; configure a strong password before publishing.
- The app does not show the score to trainees. Admin can see score and detailed answer data.
- Trainee name is collected as entered; consider your institution's privacy and retention policy before collecting personal data.
