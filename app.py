import streamlit as st
from streamlit_autorefresh import st_autorefresh
import sqlite3
import json
import hashlib
import hmac
import csv
import io
import uuid
from datetime import datetime, timezone
from pathlib import Path

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "dgit_results.sqlite3"

st.set_page_config(page_title="DGIT Training Assessment", page_icon="📝", layout="centered")

st.markdown("""
<style>
html, body, [class*="css"] { font-size: 19px !important; }
.stApp { background: #f7f9fc; }
.block-container { max-width: 1050px; padding-top: 2rem; padding-bottom: 3rem; }
h1 { font-size: 2.5rem !important; font-weight: 800 !important; }
h2 { font-size: 1.9rem !important; font-weight: 750 !important; }
h3 { font-size: 1.45rem !important; font-weight: 700 !important; }
p, label, .stMarkdown, .stRadio label, .stTextInput label { font-size: 1.12rem !important; line-height: 1.55 !important; }
.stButton button, .stFormSubmitButton button { min-height: 3.2rem; font-size: 1.15rem !important; font-weight: 700 !important; border-radius: 10px; }
div[data-testid="stRadio"] label { padding: 0.35rem 0; }
div[data-testid="stTextInput"] input { min-height: 3rem; font-size: 1.1rem !important; }
div[data-testid="stAlert"] { font-size: 1.05rem !important; }
.question-card { background: white; border: 1px solid #dce3ed; border-radius: 14px; padding: 1rem 1.2rem; margin: 0.8rem 0; }
.timer { font-size: 2rem; font-weight: 800; text-align: center; padding: .7rem; border-radius: 12px; background: #fff1d6; color: #8a4b00; }
</style>
""", unsafe_allow_html=True)

QUESTIONS = [
{"topic":"Digital Forensics","q":"A live PC may hold volatile evidence. First priority?","options":["Power off","Capture volatile data","Run cleanup","Copy user files"],"a":1,"why":"Volatile data may be lost on shutdown; capture it first using a documented process."},
{"topic":"Search and Seizure","q":"Best record for exhibit continuity?","options":["Make only","Seizure and handling log","Room photo","Officer memory"],"a":1,"why":"Identifiers, condition, timestamps and transfers establish continuity."},
{"topic":"Financial Forensics","q":"Funds pass through accounts within minutes. Best analysis?","options":["Map linked flows and times","Treat transfers alone","Ignore intermediaries","Infer intent"],"a":0,"why":"A time-ordered transaction graph can expose layering patterns."},
{"topic":"Accounting Forensics","q":"Ledger and bank credits differ. Best comparison?","options":["Tax rate","Staff list","Entry-to-transaction reconciliation","Closing balance"],"a":2,"why":"Transaction-level matching links ledger entries to bank movement."},
{"topic":"Blockchain","q":"A forum post links an address to a suspect. What is missing?","options":["Block height","Wallet balance","Fee value","Independent attribution"],"a":3,"why":"On-chain activity alone does not identify the real-world controller."},
{"topic":"Crypto Investigation","q":"A seed phrase is found near a phone. It proves:","options":["Ownership","Nothing without corroboration","A transfer","Current access"],"a":1,"why":"Context, wallet access and corroboration are needed to establish control."},
{"topic":"Money Trailing","q":"Best feature to detect pass-through payments?","options":["Account age","Branch address","Timed debit-credit links","Monthly balance"],"a":2,"why":"Temporal and relational analysis reveals rapid movement across accounts."},
{"topic":"Network Forensics","q":"Firewall logs show outbound traffic. What should be correlated?","options":["Time, NAT, endpoint and host logs","Malware assumption","IP geolocation only","Ignore clock drift"],"a":0,"why":"Correlated logs and time context help attribute traffic to a host."},
{"topic":"Dark Web OSINT","q":"Browser history shows a hidden-service URL. This proves:","options":["Illegal purchase","Operator identity","Access lead only","Downloaded content"],"a":2,"why":"History may indicate access, not purpose, user identity or completed activity."},
{"topic":"OSINT","q":"Two public profiles share a name and photo. Best next step?","options":["Assume same person","Correlate independent identifiers","Trust follower count","Publish match"],"a":1,"why":"Identity resolution needs multiple independent corroborating attributes."},
{"topic":"AI Investigations","q":"AI flags 200 of 1M records. Best use?","options":["Treat as proof","Discard others","Prioritise human review","Submit model output"],"a":2,"why":"AI supports triage; investigators must validate source evidence."},
{"topic":"Evidence Analysis","q":"A tool reports a deleted file. What must be retained?","options":["Screenshot only","Tool name","Edited copy","Image, logs and method"],"a":3,"why":"Preserved source data and documented methods support reproducibility."},
{"topic":"Wallet Tracing","q":"Funds reach an exchange after several hops. Strongest lead?","options":["Exchange account records","Address label","Wallet icon","Current balance"],"a":0,"why":"Exchange records may connect on-chain flows to an account, subject to lawful process."},
{"topic":"Mobile Forensics","q":"Why examine a SQLite WAL file?","options":["It stores images","It may hold uncheckpointed changes","It proves authorship","It replaces DB"],"a":1,"why":"A write-ahead log may contain recent changes not yet merged into the main database."},
{"topic":"Cloud Forensics","q":"A synced folder lacks a deleted cloud file. Best next source?","options":["Other PC recycle bin","Bookmarks","Provider audit/version logs","Wallpaper"],"a":2,"why":"Cloud-side audit, version and deletion records may retain relevant activity."},
{"topic":"Acquisition","q":"Matching source and image hashes support:","options":["Relevance","No deletion","Suspect authorship","Integrity of hashed data"],"a":3,"why":"Matching hashes support integrity, not completeness or relevance."},
{"topic":"Windows Forensics","q":"Which artefact may show USB connection history?","options":["USB Registry entries","Wallpaper cache","Recycle Bin icon","Screen size"],"a":0,"why":"Windows Registry artefacts can record connected USB device details."},
{"topic":"Multimedia","q":"Video metadata shows a creation time. Key caveat?","options":["Cannot be edited","May be altered; corroborate","Proves location","Proves continuity"],"a":1,"why":"Metadata can be modified and should be checked against independent evidence."},
{"topic":"IP Analysis","q":"CGNAT maps many users to one public IP. What is essential?","options":["Country lookup","Domain only","Timestamp, source port and provider logs","Reverse DNS"],"a":2,"why":"Precise time and port details are needed to correlate provider records."},
{"topic":"Evidence Integrity","q":"A forensic image hash mismatches. First action?","options":["Ignore","Edit hash","Delete source","Preserve logs and investigate"],"a":3,"why":"Stop and investigate the discrepancy; never conceal or overwrite evidence."}
]

def db_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trainee_name TEXT NOT NULL,
        organisation TEXT,
        submitted_at TEXT NOT NULL,
        score INTEGER NOT NULL,
        total INTEGER NOT NULL,
        answers_json TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS assessment_control (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        is_active INTEGER NOT NULL DEFAULT 0,
        start_at REAL,
        duration_minutes INTEGER NOT NULL DEFAULT 10
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS participants (
        participant_id TEXT PRIMARY KEY, trainee_name TEXT NOT NULL,
        organisation TEXT, joined_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Waiting'
    )""")
    conn.execute("INSERT OR IGNORE INTO assessment_control (id, is_active, start_at, duration_minutes) VALUES (1, 0, NULL, 10)")
    conn.commit()
    return conn

def get_test_control():
    conn = db_conn()
    row = conn.execute("SELECT is_active, start_at, duration_minutes FROM assessment_control WHERE id=1").fetchone()
    conn.close()
    return {"active": bool(row[0]), "start_at": row[1], "duration": int(row[2])}

def set_test_control(active, start_at=None, duration=10):
    conn = db_conn()
    conn.execute("UPDATE assessment_control SET is_active=?, start_at=?, duration_minutes=? WHERE id=1",
                 (1 if active else 0, start_at, int(duration)))
    conn.commit()
    conn.close()

def register_participant(pid, name, organisation):
    conn = db_conn()
    conn.execute("INSERT OR REPLACE INTO participants VALUES (?, ?, ?, ?, ?)",
                 (pid, name, organisation, datetime.now(timezone.utc).isoformat(), "Waiting"))
    conn.commit(); conn.close()

def list_participants():
    conn = db_conn()
    rows = conn.execute("SELECT participant_id, trainee_name, organisation, joined_at, status FROM participants ORDER BY joined_at").fetchall()
    conn.close()
    return rows

def update_participant_status(pid, status):
    conn = db_conn()
    conn.execute("UPDATE participants SET status=? WHERE participant_id=?", (status, pid))
    conn.commit(); conn.close()

def save_local(name, organisation, answers, score):
    conn = db_conn()
    conn.execute(
        "INSERT INTO submissions (trainee_name, organisation, submitted_at, score, total, answers_json) VALUES (?, ?, ?, ?, ?, ?)",
        (name, organisation, datetime.now(timezone.utc).isoformat(), score, len(QUESTIONS), json.dumps(answers))
    )
    conn.commit()
    conn.close()

def get_secret(key, default=None):
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default

def save_submission(name, organisation, answers, score):
    # Persistent cloud option: configure Google Sheets in Streamlit secrets.
    sheet_id = get_secret("GOOGLE_SHEET_ID")
    service_account = get_secret("gcp_service_account")
    if sheet_id and service_account:
        try:
            import gspread
            from google.oauth2.service_account import Credentials
            scopes = ["https://www.googleapis.com/auth/spreadsheets"]
            creds = Credentials.from_service_account_info(dict(service_account), scopes=scopes)
            client = gspread.authorize(creds)
            sheet = client.open_by_key(sheet_id).sheet1
            if not sheet.get_all_values():
                sheet.append_row(["Trainee Name", "Organisation", "Submitted At (UTC)", "Score", "Total", "Answers JSON"])
            sheet.append_row([name, organisation, datetime.now(timezone.utc).isoformat(), score, len(QUESTIONS), json.dumps(answers)])
            return "sheets"
        except Exception as e:
            st.error("Google Sheets save failed. Please contact the administrator. Submission was not saved to the cloud sheet.")
            st.exception(e)
            return None
    save_local(name, organisation, answers, score)
    return "sqlite"

def load_results():
    conn = db_conn()
    rows = conn.execute("SELECT trainee_name, organisation, submitted_at, score, total, answers_json FROM submissions ORDER BY id DESC").fetchall()
    conn.close()
    return rows

def load_sheet_results():
    import gspread
    from google.oauth2.service_account import Credentials
    scopes = ["https://www.googleapis.com/auth/spreadsheets"]
    creds = Credentials.from_service_account_info(dict(get_secret("gcp_service_account")), scopes=scopes)
    client = gspread.authorize(creds)
    sheet = client.open_by_key(get_secret("GOOGLE_SHEET_ID")).sheet1
    values = sheet.get_all_records()
    return values

def admin_password_ok(password):
    configured = get_secret("ADMIN_PASSWORD", "Nitk@12345")
    return hmac.compare_digest(str(password), str(configured))

st.title("DGIT Training Assessment")
st.caption("Digital Forensics, Investigations and Data Analytics | 20 questions")
st.info("Enter your details and complete the assessment. Your score and answers are recorded for the training administrator. Your result will not be displayed after submission.")

if "submitted" not in st.session_state:
    st.session_state.submitted = False
if "trainee_name" not in st.session_state:
    st.session_state.trainee_name = ""

page = st.sidebar.radio("Navigation", ["Trainee Assessment", "Admin"])

if page == "Trainee Assessment":
    control = get_test_control()
    now_ts = datetime.now(timezone.utc).timestamp()
    deadline = control["start_at"] + control["duration"] * 60 if control["start_at"] else None
    remaining = max(0, int(deadline - now_ts)) if deadline else 0

    if control["active"] and deadline:
        mm, ss = divmod(remaining, 60)
        timer_label = f"TIME REMAINING  {mm:02d}:{ss:02d}" if remaining else "TIME IS UP"
        st.markdown(f'<div class="timer">{timer_label}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="timer">TEST NOT STARTED — WAITING FOR ADMIN</div>', unsafe_allow_html=True)

    if st.session_state.submitted:
        st.success("Your assessment has been submitted. Thank you.")
        st.stop()

    if not st.session_state.get("registered", False):
        with st.form("trainee_registration"):
            st.subheader("Trainee registration")
            name = st.text_input("Full name *", max_chars=100)
            organisation = st.text_input("Organisation / Department", max_chars=150)
            joined = st.form_submit_button("Register and enter waiting room", type="primary", use_container_width=True)
        if joined:
            if not name.strip():
                st.error("Please enter your full name.")
                st.stop()
            pid = str(uuid.uuid4())
            st.session_state.participant_id = pid
            st.session_state.trainee_name = name.strip()
            st.session_state.organisation = organisation.strip()
            st.session_state.registered = True
            register_participant(pid, name.strip(), organisation.strip())
            st.rerun()
        st_autorefresh(interval=5000, key="registration_refresh")
        st.stop()

    if not control["active"]:
        st.success(f"Registered: {st.session_state.trainee_name}")
        st.info("You are in the waiting room. The administrator will start the test for everyone.")
        st_autorefresh(interval=3000, key="waiting_room_refresh")
        st.stop()

    if not st.session_state.get("started", False):
        if remaining <= 0:
            st.warning("The test has ended. Contact the administrator.")
            st.stop()
        st.session_state.started = True
        update_participant_status(st.session_state.participant_id, "Started")
        st.rerun()

    st_autorefresh(interval=1000, key="assessment_timer_refresh")
    if remaining <= 0:
        responses = {str(i+1): st.session_state.get(f"q_{i+1}") for i in range(len(QUESTIONS))}
        score = sum(1 for i, q in enumerate(QUESTIONS) if responses[str(i+1)] == q["options"][q["a"]])
        if save_submission(st.session_state.trainee_name, st.session_state.get("organisation", ""), responses, score):
            update_participant_status(st.session_state.participant_id, "Submitted (time expired)")
            st.session_state.submitted = True
            st.rerun()
        st.stop()

    st.markdown(f"### Assessment: {st.session_state.trainee_name}")
    with st.form("assessment_form"):
        responses = {}
        for i, q in enumerate(QUESTIONS):
            st.markdown(f'<div class="question-card"><strong>Q{i+1}.</strong> {q["q"]}</div>', unsafe_allow_html=True)
            responses[str(i+1)] = st.radio("Choose one", q["options"], index=None, key=f"q_{i+1}", label_visibility="collapsed")
            st.markdown("---")
        submitted = st.form_submit_button("Submit assessment", type="primary", use_container_width=True)
    if submitted:
        unanswered = [str(i+1) for i, q in enumerate(QUESTIONS) if responses[str(i+1)] is None]
        if unanswered:
            st.error(f"Answer all questions before submitting. Missing: {', '.join(unanswered)}")
        else:
            score = sum(1 for i, q in enumerate(QUESTIONS) if responses[str(i+1)] == q["options"][q["a"]])
            if save_submission(st.session_state.trainee_name, st.session_state.get("organisation", ""), responses, score):
                update_participant_status(st.session_state.participant_id, "Submitted")
                st.session_state.submitted = True
                st.rerun()

else:
    st.subheader("Administrator")
    if not st.session_state.get("admin_authenticated", False):
        with st.form("admin_login"):
            password = st.text_input("Admin password", type="password")
            login = st.form_submit_button("Login", type="primary")
        if login:
            if admin_password_ok(password):
                st.session_state.admin_authenticated = True
                st.rerun()
            else:
                st.error("Invalid administrator password.")
        st.caption("Set ADMIN_PASSWORD in Streamlit secrets before deployment. The default is intended only for local testing.")
        st.stop()

    st.success("Administrator access")
    st.markdown("### Registered trainees")
    participants = list_participants()
    st.metric("Trainees joined", len(participants))
    if participants:
        roster = [{"Name": p[1], "Organisation": p[2], "Joined (UTC)": p[3], "Status": p[4]} for p in participants]
        st.dataframe(roster, use_container_width=True, hide_index=True)
    else:
        st.info("No trainees have registered yet.")
    st_autorefresh(interval=5000, key="admin_roster_refresh")
    control = get_test_control()
    st.markdown("### Assessment control")
    st.write("Review the registered trainee list above before starting. The test starts for all waiting trainees when you press Start.")
    duration = st.number_input("Test duration (minutes)", min_value=1, max_value=180, value=control["duration"], step=1)
    if st.button(f"Start test for {len(participants)} registered trainees", type="primary", use_container_width=True, disabled=(len(participants) == 0)):
        set_test_control(True, datetime.now(timezone.utc).timestamp(), int(duration))
        st.success(f"Assessment started for all trainees. Duration: {int(duration)} minutes.")
        st.rerun()
    if st.button("End assessment now", use_container_width=True):
        set_test_control(False, None, int(duration))
        st.warning("Assessment has been closed for new attempts.")
        st.rerun()
    if control["active"] and control["start_at"]:
        end_at = control["start_at"] + control["duration"] * 60
        left = max(0, int(end_at - datetime.now(timezone.utc).timestamp()))
        mm, ss = divmod(left, 60)
        st.info(f"Test status: ACTIVE | Time remaining: {mm:02d}:{ss:02d}")
    else:
        st.info("Test status: NOT STARTED")
    st.markdown("---")
    if st.button("Log out"):
        st.session_state.admin_authenticated = False
        st.rerun()

    use_sheets = bool(get_secret("GOOGLE_SHEET_ID") and get_secret("gcp_service_account"))
    try:
        if use_sheets:
            records = load_sheet_results()
            if records:
                st.write(f"Total submissions: **{len(records)}**")
                st.dataframe(records, use_container_width=True, hide_index=True)
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)
                st.download_button("Download results CSV", output.getvalue(), "dgit_assessment_results.csv", "text/csv")
            else:
                st.info("No submissions recorded yet.")
        else:
            rows = load_results()
            st.write(f"Total submissions: **{len(rows)}**")
            if rows:
                display = [{
                    "Trainee Name": r[0],
                    "Organisation": r[1],
                    "Submitted At (UTC)": r[2],
                    "Score": f"{r[3]}/{r[4]}"
                } for r in rows]
                st.dataframe(display, use_container_width=True, hide_index=True)
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["Trainee Name", "Organisation", "Submitted At (UTC)", "Score", "Total", "Answers JSON"])
                writer.writerows(rows)
                st.download_button("Download detailed results CSV", output.getvalue(), "dgit_assessment_results.csv", "text/csv")
            else:
                st.info("No submissions recorded yet.")
            st.warning("SQLite mode: Streamlit Community Cloud local files may be reset when the app restarts or redeploys. Configure Google Sheets storage for persistent hosted results.")
    except Exception:
        st.error("Unable to retrieve results. Check the storage configuration.")
        st.exception(Exception("Storage retrieval failed"))
