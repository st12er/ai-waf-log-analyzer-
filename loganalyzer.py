
import streamlit as st
import pandas as pd
import os
from openai import AzureOpenAI
from dotenv import load_dotenv

# -----------------------------
# ✅ Load API
# -----------------------------
load_dotenv()

client = AzureOpenAI(
    api_key=os.environ.get("AZURE_OPENAI_API_KEY"),
    api_version="2025-04-01-preview",
    azure_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT")
)

# -----------------------------
# ✅ UI
# -----------------------------
st.title("WAF Log Analyzer + AI 🔐🤖")

# Upload CSV
uploaded_file = st.file_uploader("Upload WAF Logs", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # ✅ Clean column names
    df.columns = df.columns.str.strip().str.lower()

    # ✅ Remove empty rows (important fix)
    df = df.dropna(subset=["path", "user_agent"])

    # ✅ Convert to string to avoid float errors
    df["path"] = df["path"].astype(str)
    df["user_agent"] = df["user_agent"].astype(str)

    st.subheader("Raw Logs")
    st.write(df)

    # -----------------------------
    # ✅ Detection Logic
    # -----------------------------
    st.subheader("Advanced Threat Detection 🔍")

    df["is_bot"] = (
        df["user_agent"].str.contains("bot|python|headless", case=False, na=False)
        | (df["requests"] > 700)
    )

    df["is_scraping"] = (
        df["path"].str.contains("/api|/product", case=False, na=False)
        & (df["requests"] > 500)
    )

    df["is_cred_stuff"] = (
        (df["path"].str.contains("/login", na=False))
        & (df["requests"] > 500)
        & (df["status"] == 403)
    )

    # -----------------------------
    # ✅ Reason + Risk
    # -----------------------------
    df["reason"] = ""
    df["risk"] = "Low"

    for i, row in df.iterrows():
        reasons = []
        score = 0

        if row["requests"] > 700:
            reasons.append("High request volume")
            score += 2

        if "bot" in row["user_agent"].lower() or "python" in row["user_agent"].lower():
            reasons.append("Suspicious automation user-agent")
            score += 2

        if "/login" in row["path"] and row["status"] == 403:
            reasons.append("Login failures (credential stuffing)")
            score += 1

        if "/api" in row["path"]:
            reasons.append("Frequent API access (scraping)")
            score += 1

        df.at[i, "reason"] = ", ".join(reasons)

        if score >= 4:
            df.at[i, "risk"] = "High"
        elif score >= 2:
            df.at[i, "risk"] = "Medium"

    # -----------------------------
    # ✅ Show Results
    # -----------------------------
    st.subheader("Detection Results")

    st.write("Bot Traffic 🤖", df[df["is_bot"]])
    st.write("Scraping Activity 📡", df[df["is_scraping"]])
    st.write("Credential Stuffing 🔐", df[df["is_cred_stuff"]])

    st.subheader("Detailed Analysis 🧠")
    st.write(df[["ip", "requests", "path", "reason", "risk"]])

    # -----------------------------
    # ✅ AI Chat Section
    # -----------------------------
    user_query = st.text_input("Ask about traffic (e.g., Why is this bot?)")

    if user_query:
        sample_data = df.head(10).to_string()

        prompt = f"""
        You are a cybersecurity expert analyzing WAF logs.

        Logs:
        {sample_data}

        Question:
        {user_query}

        Explain:
        - Why this traffic is malicious or not
        - What type of attack it is
        - Suggest Akamai protection
        """

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )

        answer = response.choices[0].message.content

        st.subheader("AI Analysis 🤖")
        st.write(answer)
