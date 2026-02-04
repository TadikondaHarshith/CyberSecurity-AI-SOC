🛡 CyberSecurity AI SOC Platform

An AI-powered Security Operations Center (SOC) simulation platform built using Python and Flask that detects cyber attacks in real time, visualizes threats, manages incidents, sends alerts, blocks malicious IPs, and generates professional incident response reports.

This project demonstrates a complete Blue Team workflow:

Detection → Analysis → Response → Reporting

🚀 Features
🔍 Attack Detection

Simulated cyber attacks (DDoS, BruteForce, SQL Injection, PortScan)

AI classification logic

Severity + Risk scoring

MITRE ATT&CK mapping

📊 SOC Dashboard

Live attack table

Threat timeline graph

Geo attack visualization

Kill-chain phase tracking

Top attackers & attack distribution

🚨 Automated Response

Email alerts for high severity attacks

Automatic Windows Firewall IP blocking

Incident creation for critical threats

🗂 Incident Management

Admin / Analyst login

Close incidents

Analyst comments

Audit logging

📄 Professional SOC Reports

PDF Incident Response Report

Executive summary

Severity pie chart

Attack bar chart

Critical incident insights

Recommended actions

Generated using ReportLab + Matplotlib.

🧱 Architecture Flow
Attack Generator
        ↓
Flask API (/predict)
        ↓
Attack Classification
        ↓
Severity + Risk + MITRE
        ↓
SQLite Database
        ↓
SOC Dashboard
        ↓
Email Alert + Firewall Block
        ↓
Incident Management + PDF Report

▶ How To Run
1️⃣ Clone Repository
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO

2️⃣ Create Virtual Environment
python -m venv venv
venv\Scripts\activate

3️⃣ Install Requirements
pip install -r requirements.txt

4️⃣ Run Backend
python app.py


Open browser:

http://127.0.0.1:5000

🔐 Login

Create users manually in SQLite.

Admin role required to close incidents.

📄 Generate SOC Report

Open:

/report


PDF downloads to:

reports/SOC_Report.pdf

📂 Project Structure
Backend/
 ├── app.py
 ├── database.py
 ├── soc.db
 ├── reports/
 ├── templates/
 └── static/

🎯 Use Cases

SOC simulation

Cybersecurity learning

Hackathon demo

Resume project

Blue Team practice

👨‍💻 Author

Harshith Tadikonda

⚠ Disclaimer

Educational project only.
Do NOT deploy to production.

⭐ If you like this project, give it a star!

## 📸 Screenshots

### SOC Dashboard
![Dashboard](screenshots/dashboard.png)

### Incident Management
![Incidents](screenshots/incidents.png)

### AI SOC Report
![Report](screenshots/report.png)


🧠 Resume Bullet

Built an AI-powered SOC platform using Python & Flask featuring real-time attack detection, MITRE mapping, automated firewall blocking, incident management, and executive PDF reporting.

🔥 GitHub Description

AI-powered Security Operations Center platform with real-time attack detection, automated response, incident management, and professional SOC reporting.