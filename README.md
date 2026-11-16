# DGIT Training Assessment App

## Features
- 50-question application-oriented question bank; each test session randomly selects 15 questions.
- Every trainee in one Test ID receives the same 15 questions, but in a separately shuffled order.
- Skipped questions are permitted. Before final submission, the trainee is told how many questions were attempted and missed.
- Auto-refresh for trainees and administrators; waiting trainees are automatically moved into the quiz when the test starts.
- Refresh-safe saved answers and remaining time.
- Administrator can restart all trainees under a new Test ID, restart an individual trainee, pause/resume an individual trainee, or reset an individual trainee to waiting.
- Activity logs capture registration, test start, answer saves, submissions, pause/resume, restart/reset events.

## Deployment
Replace the repository's `app.py` and `requirements.txt` with the files in this ZIP. Preserve existing Streamlit Secrets.

## Important persistence note
This version uses SQLite. Streamlit Community Cloud local storage may be reset during restarts/redeployments, and local SQLite is not a safe shared store for multiple app replicas. For durable production use, migrate participant state, test sessions, answers, and logs to a shared PostgreSQL/Supabase database.
