# **PhishGuard – AI-Based Phishing Detection & Awareness System**
### **Zoho CliqTrix 2025 – Project Documentation**
---

## **1. Project Overview**
**PhishGuard** is an AI-assisted phishing detection and employee security‑awareness platform designed to help organizations identify malicious URLs, suspicious emails, and phishing indicators. It includes:

- 🔍 **Phishing Detection Engine (Python Backend)**
- 📊 **Interactive Security Dashboard (Streamlit)**
- 🧠 **Real‑time URL & Email Analysis**
- 🛡️ **Threat Score Generation**
- 📈 **Employee Awareness Scoring**

The system is designed as a **standalone productivity/security tool** which can be integrated with any corporate chat or used independently during internal security operations.

---

## **2. Key Features**
### ✅ **Phishing Detection API (Backend)**
- Domain age lookup (WHOIS)
- SSL certificate validation
- Redirect depth checking
- Suspicious keyword detection
- Threat score calculation

### ✅ **Streamlit Security Dashboard**
- URL scanner UI
- Threat breakdown report
- Recent scans table
- Awareness score tracking
- Attractive, professional UI

### ✅ **Employee Awareness Scoring**
The system maintains a simple scoring model:
- Correctly flagged phishing → +10
- Legitimate but reported → +2
- Missed phishing → -5

---

## **3. System Architecture**
```
User
 ↓
Streamlit Dashboard (Frontend)
 ↓
Python Backend (FastAPI/Flask)
 ↓
Threat Intelligence Logic (WHOIS, SSL, Redirects)
 ↓
Phishing Risk Score
 ↓
Streamlit UI Response
```

---

## **4. Backend Setup (Python)**
### **Requirements**
Install dependencies:
```
pip install flask requests python-whois
```

### **Run the Backend**
```
python backend.py
```
Backend runs at:
```
http://localhost:8000
```

---

## **5. Dashboard Setup (Streamlit)**
### **Install Streamlit**
```
pip install streamlit
```

### **Create Secrets File**
Create `.streamlit/secrets.toml`:
```
backend_url = "http://localhost:8000"
```

### **Run the Dashboard**
```
streamlit run dashboard_app.py
```

---

## **6. How the System Works**

### **Step 1 — User Inputs URL or Email Text**
User enters a suspicious URL in the dashboard:
```
https://login-verify-account-security.com
```

### **Step 2 — Backend Performs Multi‑Layer Analysis**
- Domain age: 3 days
- SSL certificate: Invalid
- Redirects: 4
- URL pattern: Contains "verify", "account", "login"

### **Step 3 — Threat Score Assigned**
Example:
```
Threat Level: HIGH
```

### **Step 4 — Dashboard Displays Result**
A full card-style report is shown with color-coded severity.

### **Step 5 — Entry Logged into History**
User can track:
- Previously scanned URLs
- Threat levels
- Dates
- Awareness score

---

## **7. Screenshots (Mock Layout Included)**

### **Dashboard Home**
```
+-------------------------------------------------------------+
|  PhishGuard Dashboard                                        |
|--------------------------------------------------------------|
|  Enter URL to Scan:                                          |
|  [ https://example.com             ]  (Scan Button)           |
|--------------------------------------------------------------|
|  Recent Scans:                                               |
|  URL                         | Score  | Date                 |
|  ----------------------------------------------------------- |
|  fakebank-login.com         | HIGH   | 2025-11-18 02:30 PM   |
|  example.org                | LOW    | 2025-11-18 02:20 PM   |
+-------------------------------------------------------------+
```

### **Threat Report Card**
```
╔══════════════════════════════════════════╗
║ ⚠️  High Risk Phishing URL Detected       ║
╠══════════════════════════════════════════╣
║ Domain Age: 3 days                       ║
║ SSL Certificate: ❌ Invalid               ║
║ Redirects: 4                              ║
║ Suspicious Keywords: login, verify       ║
╚══════════════════════════════════════════╝
```

These visual mockups can be replaced with actual screenshots from your system when running.

---

## **8. Project Folder Structure**
```
Cliqtrix/
│
├── backend.py
├── dashboard_app.py
├── requirements.txt
├── .streamlit/
│     └── secrets.toml
└── data/
      └── scans.json
```

---

## **9. Deployment (Optional)**
### **Backend**
- Render.com
- Railway.app
- PythonAnywhere

### **Dashboard**
- Streamlit Cloud

---

## **10. Future Enhancements**
✔ Integration with Zoho Cliq
✔ VirusTotal API scanning
✔ Email header analysis
✔ PDF Report Export
✔ Admin Panel with Analytics
✔ Machine Learning–based phishing classifier

---

## **11. Conclusion**
**PhishGuard** provides an efficient, lightweight, and powerful phishing detection system with:
- Real‑time analysis
- User-friendly dashboard
- Employee awareness tracking
- Modern, professional interface

This project demonstrates both technical depth and UI presentation — perfect for Zoho CliqTrix.

---

### **Submitted By:**
**Pranav V**

### **Project:** **PhishGuard – AI‑Based Phishing Detection & Awareness Tool**

