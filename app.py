import streamlit as st
import sqlite3
import json
import hashlib
import hmac
import csv
import io
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
    {
        "topic": "Introduction to Digital Forensics",
        "q": "During an investigation, an officer receives a laptop that may contain evidence of undisclosed financial activity. Which approach best reflects digital-forensic practice?",
        "options": [
            "Browse files directly and copy only documents that look relevant",
            "Preserve the device, document handling, acquire data using a suitable forensic process, and verify integrity",
            "Start the operating system and allow normal updates before collecting data",
            "Rename suspicious files so they can be identified easily"
        ],
        "a": 1,
        "why": "A defensible process preserves the source, documents handling, uses an appropriate acquisition method, and checks integrity."
    },
    {
        "topic": "Search, Seizure & Investigation Techniques",
        "q": "At a search location, an officer takes custody of several digital devices. Which record is most important to maintain traceability from seizure through examination?",
        "options": [
            "A list of device brands only",
            "A note of the officer's first impression",
            "A documented seizure/acquisition record with identifiers, date, time, condition and handling details",
            "A screenshot of the desktop wallpaper"
        ],
        "a": 2,
        "why": "Documented seizure and acquisition details support traceability and accountability for each item."
    },
    {
        "topic": "Financial & Accounting Forensics",
        "q": "A business reports low income, but bank statements show repeated transfers between related accounts. What should an investigator do first?",
        "options": [
            "Map the transactions, counterparties, dates and amounts to identify financial trails",
            "Assume every transfer is tax evasion",
            "Delete duplicate-looking entries from the working copy",
            "Examine only the closing balance"
        ],
        "a": 0,
        "why": "Transaction mapping helps reveal relationships and patterns while avoiding premature conclusions."
    },
    {
        "topic": "Financial & Accounting Forensics",
        "q": "An investigator needs to examine accounting entries and compare them with supporting records. Which source/tool was specifically included in the training schedule?",
        "options": [
            "Tally and financial/accounting tools",
            "A packet-sniffing tool only",
            "A disk defragmenter",
            "A video transcoder"
        ],
        "a": 0,
        "why": "The financial-forensics sessions included Tally and financial/accounting tools."
    },
    {
        "topic": "Blockchain Investigations",
        "q": "An address on a public blockchain is suspected of receiving proceeds from a transaction. Which statement is the most appropriate starting point?",
        "options": [
            "The address automatically reveals the legal identity of its controller",
            "Public transaction records can help trace flows, but attribution requires additional evidence",
            "Blockchain transactions can always be reversed by the investigator",
            "A wallet address is the same thing as a bank account number"
        ],
        "a": 1,
        "why": "Blockchain records can support transaction tracing, but an address alone does not establish the real-world identity of its controller."
    },
    {
        "topic": "Cryptocurrency Seizure",
        "q": "During a cryptocurrency investigation, officers identify a wallet application on a seized phone. What is the best investigative interpretation?",
        "options": [
            "The application alone proves the phone owner controlled every associated asset",
            "The application is irrelevant if no cash is found",
            "The application may provide leads; wallet access, ownership and transaction links need corroboration",
            "The wallet should be opened and funds transferred immediately"
        ],
        "a": 2,
        "why": "Wallet applications can provide leads, but control and ownership must be established through corroborating evidence and proper procedures."
    },
    {
        "topic": "Investigative Data Analytics (Money Trailing)",
        "q": "A spreadsheet contains thousands of payments. The objective is to identify possible layering across accounts. Which analytical step is most useful?",
        "options": [
            "Sort only by beneficiary name and ignore dates",
            "Remove small transactions before analysis",
            "Review only transactions made on weekends",
            "Normalize transaction fields and analyse sequences, timing, amounts and linked accounts"
        ],
        "a": 3,
        "why": "Consistent fields and relationship analysis help identify transaction chains and patterns across accounts."
    },
    {
        "topic": "Network Forensics",
        "q": "A company server is suspected of communicating with an external system during the period under investigation. Which evidence is most directly relevant to network forensics?",
        "options": [
            "Network traffic records, connection metadata and relevant server/network logs",
            "The colour of the server rack",
            "The printed organisational chart alone",
            "The laptop screen resolution"
        ],
        "a": 0,
        "why": "Network forensics examines communications and related network/server records."
    },
    {
        "topic": "Dark Web Investigation using OSINT",
        "q": "An investigator is explaining the difference between the Surface Web, Deep Web and Dark Web to a team. Which description is the most accurate?",
        "options": [
            "All three terms refer to the same set of publicly indexed websites",
            "The Dark Web is a subset of the Deep Web that typically requires specific software or configurations to access",
            "The Deep Web contains only illegal marketplaces",
            "The Surface Web cannot be accessed using ordinary browsers"
        ],
        "a": 1,
        "why": "The Dark Web is generally described as a portion of the Deep Web accessed through specialised tools or configurations; the Deep Web is not limited to illegal content."
    },
    {
        "topic": "Open-Source Intelligence",
        "q": "An officer is asked to gather publicly available information about a company and its associated online presence. Which action best fits OSINT?",
        "options": [
            "Attempt to access private accounts using guessed passwords",
            "Install monitoring software on an employee's device without authority",
            "Collect and document relevant information from lawful, publicly accessible sources",
            "Treat an anonymous online post as verified fact"
        ],
        "a": 2,
        "why": "OSINT involves collecting and analysing information from open sources, with careful documentation and validation."
    },
    {
        "topic": "AI in Investigations",
        "q": "An investigation team has millions of records and wants to prioritise material for human review. What is an appropriate role for AI-assisted analytics?",
        "options": [
            "Replace evidence preservation and chain-of-custody procedures",
            "Automatically declare a person guilty based on a model score",
            "Alter source records to make patterns easier to detect",
            "Help reduce the search space and identify material for investigator verification"
        ],
        "a": 3,
        "why": "AI can help prioritise and analyse large datasets, but findings require human review and evidential validation."
    },
    {
        "topic": "Hands-on Digital Evidence Analysis",
        "q": "During a practical exercise, a trainee is asked to analyse a digital image and prepare findings. Which output is most useful for a defensible examination?",
        "options": [
            "A report describing the method, relevant observations, tools and limitations",
            "A verbal statement that the image looked suspicious",
            "A cropped image without retaining the source",
            "A conclusion without recording how it was reached"
        ],
        "a": 0,
        "why": "A useful forensic report records the process, observations, tools and limitations so the work can be reviewed."
    },
    {
        "topic": "Blockchain Wallet Tracing",
        "q": "Investigators observe funds moving through several blockchain addresses. Which method best supports a fund-flow analysis?",
        "options": [
            "Assume every address belongs to one person",
            "Record transaction identifiers, timestamps, amounts and address relationships, then seek attribution evidence",
            "Ignore intermediary addresses",
            "Use wallet balance alone to infer the full transaction history"
        ],
        "a": 1,
        "why": "A transaction-level flow map preserves the observable trail while keeping attribution as a separate evidential question."
    },
    {
        "topic": "Mobile Device Forensics",
        "q": "A seized Android phone may contain relevant images and messages. Which approach is most appropriate before drawing conclusions from the extracted data?",
        "options": [
            "Use the phone normally for a few days to see what appears",
            "Delete irrelevant-looking applications",
            "Document the device and acquisition process, examine the acquired data, and correlate findings",
            "Rely only on the gallery thumbnails"
        ],
        "a": 2,
        "why": "Proper documentation, suitable acquisition and correlation of extracted artefacts support reliable mobile examination."
    },
    {
        "topic": "Cloud Forensics",
        "q": "An investigation concerns files believed to be stored in a cloud service. What is a key first consideration?",
        "options": [
            "Assume the local computer contains every cloud record",
            "Ask the provider to delete duplicate data",
            "Use another person's credentials to access the account",
            "Identify the service, relevant account/data, available logs and lawful process for obtaining evidence"
        ],
        "a": 3,
        "why": "Cloud investigations require identifying where data and logs reside and following the appropriate lawful acquisition process."
    },
    {
        "topic": "Practical Investigation Techniques",
        "q": "Why is a write blocker used when acquiring data from a storage device?",
        "options": [
            "To prevent writes to the source media during the acquisition process",
            "To increase the storage capacity of the device",
            "To decrypt every file automatically",
            "To remove malware before imaging"
        ],
        "a": 0,
        "why": "A write blocker helps protect the source media from modification during forensic acquisition."
    },
    {
        "topic": "Windows and System Forensics",
        "q": "A computer may have been used to access files and run applications. Which combination is most relevant to a Windows/system forensic examination?",
        "options": [
            "Monitor brightness and desktop wallpaper",
            "Registry information, Windows artefacts and memory-related evidence",
            "Printer colour settings only",
            "The physical dimensions of the keyboard"
        ],
        "a": 1,
        "why": "Registry data, operating-system artefacts and memory can provide information about system activity."
    },
    {
        "topic": "Multimedia Forensics",
        "q": "A video submitted as evidence is suspected to have been edited. Which examination is most relevant?",
        "options": [
            "Check only the file name",
            "Convert it to a smaller format and discard the original",
            "Examine the media, metadata and relevant image/video characteristics while preserving the original",
            "Assume that a high-resolution video is authentic"
        ],
        "a": 2,
        "why": "Multimedia forensics examines media content and metadata, while preservation of the original is essential."
    },
    {
        "topic": "Digital Evidence Analysis",
        "q": "An investigator finds an IP address in a set of extracted records. What is the most defensible interpretation?",
        "options": [
            "It conclusively identifies the individual user",
            "It proves the device was physically present at a particular location",
            "It is sufficient by itself to establish criminal intent",
            "It is an investigative lead that should be correlated with timestamps, logs, provider records and other evidence"
        ],
        "a": 3,
        "why": "An IP address is a technical identifier and must be interpreted with timing, network context and corroborating evidence."
    },
    {
        "topic": "Evidence Integrity",
        "q": "A forensic image is acquired and a cryptographic hash is calculated. The same hash is obtained when the image is verified later. What does this support?",
        "options": [
            "The image contains no deleted data",
            "The image has remained unchanged between the two hash calculations, subject to the hash algorithm's properties",
            "The source device was never used",
            "Every file in the image is relevant to the case"
        ],
        "a": 1,
        "why": "Matching hashes support that the hashed data has not changed between the two calculations; they do not prove relevance or completeness."
    },
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
    deadline = (control["start_at"] + control["duration"] * 60) if control["start_at"] else None
    remaining = max(0, int(deadline - now_ts)) if deadline else 0

    if st.session_state.submitted:
        st.success("Your assessment has been submitted successfully.")
        st.write("Thank you for completing the assessment. Your response has been recorded.")
        st.stop()

    if not control["active"] or not control["start_at"]:
        st.warning("The administrator has not started the assessment yet. Please wait for the invigilator's instruction.")
        st.info("Once the administrator starts the test, you can enter your name and begin.")
        st.stop()

    if remaining <= 0:
        if not st.session_state.get("started", False):
            st.error("The assessment time has ended. You did not start the test in time.")
            st.stop()
        responses = {str(i+1): st.session_state.get(f"q_{i+1}") for i in range(len(QUESTIONS))}
        score = sum(1 for i, q in enumerate(QUESTIONS) if responses[str(i+1)] == q["options"][q["a"]])
        save_mode = save_submission(st.session_state.trainee_name, st.session_state.get("organisation", ""), responses, score)
        if save_mode:
            st.session_state.submitted = True
            st.rerun()
        st.stop()

    st_autorefresh(interval=1000, key="assessment_timer_refresh")
    mins, secs = divmod(remaining, 60)
    st.markdown(f'<div class="timer">TIME REMAINING&nbsp;&nbsp; {mins:02d}:{secs:02d}</div>', unsafe_allow_html=True)

    if not st.session_state.get("started", False):
        with st.form("trainee_details"):
            st.subheader("Trainee details")
            name = st.text_input("Trainee full name *", max_chars=100)
            organisation = st.text_input("Organisation / Department", max_chars=150)
            st.markdown("---")
            st.subheader("Assessment instructions")
            st.write("• 20 moderate-difficulty multiple-choice questions")
            st.write("• One correct answer per question")
            st.write("• The countdown is controlled by the administrator and is shared by all trainees")
            st.write("• Your score and answers will not be displayed after submission")
            start = st.form_submit_button("Enter assessment", type="primary", use_container_width=True)
        if start:
            if not name.strip():
                st.error("Please enter your full name before proceeding.")
                st.stop()
            st.session_state.trainee_name = name.strip()
            st.session_state.organisation = organisation.strip()
            st.session_state.started = True
            st.rerun()
        st.stop()

    st.markdown(f"### Assessment for {st.session_state.trainee_name}")
    st.caption("The test ends automatically when the administrator-set timer reaches zero.")
    with st.form("assessment_form"):
        responses = {}
        for i, q in enumerate(QUESTIONS):
            st.markdown(f'<div class="question-card"><strong>Question {i+1} of {len(QUESTIONS)}</strong><br>{q["q"]}</div>', unsafe_allow_html=True)
            responses[str(i+1)] = st.radio("Select one answer", q["options"], index=None,
                                           key=f"q_{i+1}", label_visibility="collapsed")
            st.caption(f"Topic: {q['topic']}")
            st.markdown("---")
        submitted = st.form_submit_button("Submit assessment", type="primary", use_container_width=True)
    if submitted:
        unanswered = [str(i+1) for i, q in enumerate(QUESTIONS) if responses[str(i+1)] is None]
        if unanswered:
            st.error(f"Please answer all questions. Unanswered question numbers: {', '.join(unanswered)}")
        else:
            score = sum(1 for i, q in enumerate(QUESTIONS) if responses[str(i+1)] == q["options"][q["a"]])
            save_mode = save_submission(st.session_state.trainee_name, st.session_state.get("organisation", ""), responses, score)
            if save_mode:
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
    control = get_test_control()
    st.markdown("### Assessment control")
    st.write("The administrator controls when the test becomes available and the shared countdown duration.")
    duration = st.number_input("Test duration (minutes)", min_value=1, max_value=180, value=control["duration"], step=1)
    if st.button("Start / Restart test for all trainees", type="primary", use_container_width=True):
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
