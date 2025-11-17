"""
dashboard_app.py
Streamlit dashboard for PhishGuard POC.
Interacts with the FastAPI backend to submit URLs/messages, show submissions,
leaderboard, and allow feedback marking.
"""

import streamlit as st
import pandas as pd
import requests
from datetime import datetime
import plotly.express as px

BACKEND = "http://localhost:8000"

st.set_page_config(page_title="PhishGuard Dashboard", layout="wide", initial_sidebar_state="expanded")

# ---------- Sidebar ----------
st.sidebar.title("PhishGuard")
st.sidebar.markdown("**Phishing Detection & Awareness (POC)**")
st.sidebar.markdown("Submit a suspicious URL or message, view results and track user scores.")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", ["Submit", "Submissions", "Leaderboard", "About"])

# ---------- Helper functions ----------
def call_analyze(payload):
    try:
        resp = requests.post(f"{BACKEND}/api/analyze", json=payload, timeout=12)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def get_submissions():
    try:
        resp = requests.get(f"{BACKEND}/api/submissions")
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def get_userscores():
    try:
        resp = requests.get(f"{BACKEND}/api/userscores")
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

def post_feedback(submission_id, feedback):
    try:
        resp = requests.post(f"{BACKEND}/api/feedback", data={"submission_id": submission_id, "feedback": feedback})
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

# ---------- Pages ----------
if page == "Submit":
    st.title("PhishGuard — Submit Suspicious Content")
    with st.form("submit_form"):
        user_id = st.text_input("Reporter (user id or name)", value="test_user")
        mode = st.radio("Submission type", ["URL", "Message/Text"], horizontal=True)
        if mode == "URL":
            text = st.text_input("Enter URL (include http/https)", value="http://example.com/login")
        else:
            text = st.text_area("Paste message or email body here")
        submitted = st.form_submit_button("Analyze")
    if submitted:
        payload = {"user_id": user_id, "source": "dashboard", "message": text}
        if mode == "URL":
            payload["urls"] = [text]
        with st.spinner("Analyzing..."):
            res = call_analyze(payload)
        if "error" in res:
            st.error("Error: " + res["error"])
        else:
            st.success(f"Verdict: {res['verdict'].upper()} (score {res['score']})")
            st.markdown("**Reasons:**")
            if res.get("reasons"):
                for r in res["reasons"]:
                    st.write("- " + r)
            st.json(res)

elif page == "Submissions":
    st.title("Recent Submissions")
    data = get_submissions()
    if "error" in data:
        st.error(data["error"])
    else:
        subs = data.get("submissions", [])
        if not subs:
            st.info("No submissions yet.")
        else:
            df_rows = []
            for s in subs:
                df_rows.append({
                    "id": s["id"],
                    "user": s["user_id"],
                    "verdict": s["verdict"],
                    "score": s["score"],
                    "reasons": "; ".join(s["reasons"]) if s.get("reasons") else "",
                    "created_at": s["created_at"]
                })
            df = pd.DataFrame(df_rows)
            st.dataframe(df, use_container_width=True)

            # interactive: select a row to view details & mark feedback
            st.markdown("---")
            st.subheader("Inspect / Feedback")
            selected_id = st.number_input("Enter submission id to inspect", min_value=1, value=df_rows[0]["id"])
            selected = next((x for x in subs if x["id"] == selected_id), None)
            if selected:
                st.write("**Submission details**")
                st.write("User:", selected["user_id"])
                st.write("Message:", selected["message"])
                st.write("URLs:", selected["urls"])
                st.write("Verdict:", selected["verdict"])
                st.write("Score:", selected["score"])
                st.write("Reasons:")
                for r in selected["reasons"]:
                    st.write("- " + r)
                st.write("Feedback:", selected["feedback"])
                st.markdown("**Mark feedback**")
                fb = st.radio("Mark as", ["safe", "malicious"], index=0, horizontal=True)
                if st.button("Submit feedback"):
                    res = post_feedback(selected_id, fb)
                    if "error" in res:
                        st.error(res["error"])
                    else:
                        st.success("Feedback submitted.")
            else:
                st.info("Submission id not found in recent list.")

elif page == "Leaderboard":
    st.title("Phishing Awareness Leaderboard")
    data = get_userscores()
    if "error" in data:
        st.error(data["error"])
    else:
        users = data.get("users", [])
        if not users:
            st.info("No user data available yet.")
        else:
            df = pd.DataFrame(users)
            df = df.sort_values("awareness_score", ascending=False)
            st.dataframe(df[["user_id","display_name","total_reports","correct_reports","false_positives","awareness_score"]], use_container_width=True)
            fig = px.bar(df, x="display_name", y="awareness_score", title="Awareness Score by User")
            st.plotly_chart(fig, use_container_width=True)

elif page == "About":
    st.title("About PhishGuard POC")
    st.markdown("""
    **PhishGuard** is a proof-of-concept phishing detection & awareness tool.
    - Backend: FastAPI (heuristic analyzer)
    - Dashboard: Streamlit
    - DB: SQLite

    This POC is intended for demo/competition use. Replace heuristics with ML and add threat-intel for production.
    """)
    st.markdown("**Quick tips:**")
    st.markdown("- Use the **Submit** page to test different URLs and messages.")
    st.markdown("- The **Submissions** page shows the list; use the ID to apply feedback.")
    st.markdown("- Leaderboard shows a simple awareness score computed from feedback.")
