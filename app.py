
import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(
    page_title="Sentinel SIEM",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp { background-color: #0b1120; color: #e5e7eb; }
[data-testid="stSidebar"] { background-color: #111827; }
[data-testid="stMetric"] {
    background: #172033;
    padding: 16px;
    border-radius: 12px;
    border: 1px solid #29364d;
}
</style>
""", unsafe_allow_html=True)

# LOGIN PAGE
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🛡️ SENTINEL")
    st.subheader("Security Information and Event Management")
    st.write("Please log in to access your dashboard.")

    with st.form("login"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

    if submitted:
        try:
            correct_user = st.secrets["auth"]["username"]
            correct_password = st.secrets["auth"]["password"]

            if username == correct_user and password == correct_password:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Incorrect username or password.")
        except Exception:
            st.error("Credentials not found. Check secrets.toml.")

    st.caption("Local educational demonstration.")
    st.stop()

# SAMPLE SECURITY LOGS
sample_logs = pd.DataFrame([
    {"Time": "10:01:12", "IP Address": "192.168.1.10",
     "Event": "Successful Login"},
    {"Time": "10:02:35", "IP Address": "185.220.101.5",
     "Event": "Failed Login"},
    {"Time": "10:02:50", "IP Address": "185.220.101.5",
     "Event": "Failed Login"},
    {"Time": "10:03:05", "IP Address": "185.220.101.5",
     "Event": "Failed Login"},
    {"Time": "10:03:20", "IP Address": "185.220.101.5",
     "Event": "Failed Login"},
    {"Time": "10:04:08", "IP Address": "192.168.1.15",
     "Event": "File Access"},
    {"Time": "10:05:15", "IP Address": "192.168.1.22",
     "Event": "Permission Denied"},
    {"Time": "10:06:30", "IP Address": "192.168.1.22",
     "Event": "Malware Detection"},
])

# SIDEBAR
with st.sidebar:
    st.title("🛡️ SENTINEL")
    page = st.radio(
        "Navigation",
        ["Overview", "Event Logs", "Threat Alerts", "IP Analysis", "About"]
    )

    uploaded_file = st.file_uploader(
        "Upload security CSV",
        type=["csv"]
    )

    if st.button("Logout"):
        st.session_state.authenticated = False
        st.rerun()

# LOAD LOGS
if uploaded_file:
    try:
        logs = pd.read_csv(uploaded_file)
    except Exception as error:
        st.error(f"Unable to read CSV: {error}")
        st.stop()
else:
    logs = sample_logs.copy()
    st.info("Demo mode: showing sample security logs.")

required = {"Time", "IP Address", "Event"}
missing = required - set(logs.columns)

if missing:
    st.error("CSV missing columns: " + ", ".join(sorted(missing)))
    st.stop()

for column in ["Time", "IP Address", "Event"]:
    logs[column] = logs[column].fillna("").astype(str).str.strip()

# DETECTION RULES
events = logs["Event"].str.lower()

failed = events.str.contains(
    r"failed login|login failed|authentication failure|invalid password",
    regex=True,
    na=False
)

suspicious = events.str.contains(
    r"malware|ransomware|unauthorized access|sql injection|"
    r"port scan|permission denied|privilege escalation",
    regex=True,
    na=False
)

counts = logs.loc[failed].groupby("IP Address").size()
brute_ips = set(counts[counts >= 3].index)

logs["Severity"] = "Low"
logs["Alert"] = "No alert"

logs.loc[failed, "Severity"] = "Medium"
logs.loc[failed, "Alert"] = "Failed login attempt"

logs.loc[suspicious, "Severity"] = "High"
logs.loc[suspicious, "Alert"] = "Suspicious event"

brute_rows = failed & logs["IP Address"].isin(brute_ips)

logs.loc[brute_rows, "Severity"] = "Critical"
logs.loc[brute_rows, "Alert"] = "Possible brute-force attempt"

# PAGE HEADER
st.title("🛡️ Mini SIEM Dashboard")
st.caption("Security monitoring and log analysis")
st.divider()

if page == "Overview":
    a, b, c, d = st.columns(4)
    a.metric("Total Events", len(logs))
    b.metric("Failed Logins", int(failed.sum()))
    c.metric("Alerts", int((logs["Alert"] != "No alert").sum()))
    d.metric("Critical Events", int((logs["Severity"] == "Critical").sum()))

    left, right = st.columns(2)

    with left:
        st.subheader("Events by Severity")
        st.bar_chart(logs["IP Address"].value_counts().head(10))

    with right:
        st.subheader("Top Source IPs")
        st.bar_chart(logs["IP Address"].value_counts().head(10))

    st.subheader("Recent Security Events")
    st.dataframe(logs, use_container_width=True, hide_index=True)

    st.download_button(
        "Download analyzed logs",
        logs.to_csv(index=False).encode("utf-8"),
        "siem_report.csv",
        "text/csv"
    )

elif page == "Event Logs":
    st.subheader("📋 Event Log Explorer")

    severity = st.selectbox(
        "Filter severity",
        ["All"] + sorted(logs["Severity"].unique().tolist())
    )
    ip_search = st.text_input("Search IP address")
    event_search = st.text_input("Search event")

    result = logs.copy()

    if severity != "All":
        result = result[result["Severity"] == severity]

    if ip_search:
        result = result[result["IP Address"].str.contains(
            ip_search, case=False, regex=False, na=False
        )]

    if event_search:
        result = result[result["Event"].str.contains(
            event_search, case=False, regex=False, na=False
        )]

    st.dataframe(result, use_container_width=True, hide_index=True)

    st.download_button(
        "Download filtered logs",
        result.to_csv(index=False).encode("utf-8"),
        "filtered_logs.csv",
        "text/csv"
    )

elif page == "Threat Alerts":
    st.subheader("🚨 Threat Alert Center")
    alerts = logs[logs["Alert"] != "No alert"]

    if alerts.empty:
        st.success("No alerts detected by current rules.")
    else:
        st.warning("Alerts need investigation; they do not prove an attack.")
        st.dataframe(alerts, use_container_width=True, hide_index=True)

elif page == "IP Analysis":
    st.subheader("🌐 IP Address Analysis")

    summary = logs.groupby("IP Address").agg(
        Total_Events=("Event", "size"),
        Failed_Logins=("Event", lambda x: int(
            x.str.lower().str.contains(
                r"failed login|login failed|authentication failure|invalid password",
                regex=True,
                na=False
            ).sum()
        )),
        Critical_Events=("Severity", lambda x: int((x == "Critical").sum()))
    ).reset_index()

    st.dataframe(summary, use_container_width=True, hide_index=True)

elif page == "About":
    st.subheader("About SENTINEL")
    st.write("""
    SENTINEL is an educational Mini SIEM project built using Python,
    Streamlit and Pandas.

    Features:
    - CSV security log upload
    - Failed-login analysis
    - Possible brute-force indicators
    - Suspicious event keyword detection
    - Severity filtering
    - IP analysis
    - Downloadable reports

    Limitations:
    - This is not a live monitoring system.
    - Detection rules can produce false positives.
    - Repeated login failures are counted across the uploaded file,
      not within a time window.
    - The demo login is not intended for public deployment.
    """)

st.divider()
st.caption("SENTINEL • Educational project • " + datetime.now().strftime("%Y-%m-%d %H:%M"))
