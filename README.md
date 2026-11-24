# DGIT Training Assessment App — Fixed Start and Persistent Results

## Fix included
The previous build used `random.SystemRandom()` to select the 15 questions but did not import `random`. This caused the administrator's Start Test action to fail. The import is now included.

## Assessment
- 50-question bank; 15 questions randomly selected for each Test ID.
- All trainees in the same Test ID receive the same 15 questions in individually shuffled order.
- Skipped questions are allowed; the trainee sees attempted and unanswered counts before final submission.
- Individual restart/pause/resume and group restart controls remain available.
- The title and page description now correctly show the 50-question bank and 15-question test.

## Persistent results file on GitHub (recommended)
Streamlit Community Cloud's local filesystem is not guaranteed to survive restarts or redeployments. To persist the results in an actual file, create a GitHub fine-grained personal access token with **Contents: Read and write** access to the repository that hosts this app.

Add these values in Streamlit Cloud → App → Settings → Secrets:

```toml
GITHUB_TOKEN = "github_pat_xxxxxxxxx"
GITHUB_REPOSITORY = "YOUR_GITHUB_USERNAME/YOUR_REPOSITORY"
GITHUB_BRANCH = "main"
GITHUB_RESULTS_FILE = "data/dgit_results.json"
```

The app creates/updates `data/dgit_results.json` in the repository whenever a trainee submits. The Admin page reads the persistent file after restarts and offers a CSV download. Results are also written to local SQLite and a local CSV backup.

Keep the GitHub repository private if the results contain trainee personal information. Do not commit the token to GitHub or place it in `app.py`.

## Deploy
Replace `app.py` and `requirements.txt` in GitHub with the versions in this ZIP. Preserve the admin password secret. If you do not configure GitHub secrets, the app still runs but only local files are used and those are not guaranteed to persist on Streamlit Cloud.
