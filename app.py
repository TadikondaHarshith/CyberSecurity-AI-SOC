from flask import Flask, request, jsonify, render_template
from database import init_db, insert_attack, fetch_logs
import requests
import smtplib
import subprocess
import sqlite3, datetime
from database import create_incident
from flask import session, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from flask import send_file
from reportlab.platypus import Image
import matplotlib.pyplot as plt
import os
from collections import Counter

ABUSE_API_KEY="10d1410addb0e2cd7f86bfcc20c131837306982ce86bbefc4717c56338c4e953f4de9fb9a8e157c1"
attack_counter = 0


app = Flask(__name__)

print("[SOC] App started")

# ================= EMAIL CONFIG =================

EMAIL_FROM = "harshith2007tadikonda@gmail.com"
EMAIL_PASS = "uwhpibgjfpnctldy"
EMAIL_TO   = "harshith2007tadikonda@gmail.com"

def block_ip(ip):

    # Never block yourself
    if ip == "127.0.0.1":
        print("[SOC] Skipping localhost block")
        return

    try:
        print("[SOC] Blocking IP in Windows Firewall:", ip)

        cmd = f'netsh advfirewall firewall add rule name="SOC_Block_{ip}" dir=in action=block remoteip={ip}'
        subprocess.run(cmd, shell=True)

        print("[SOC] IP BLOCKED:", ip)

    except Exception as e:
        print("[SOC] Block error:", e)



def send_email(subject, body):

    try:
        print("[SOC] Sending email alert...")

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.ehlo()
        server.starttls()
        server.ehlo()

        server.login(EMAIL_FROM, EMAIL_PASS)

        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()

        print("[SOC] Email sent successfully")

    except Exception as e:
        print("🔥 SOC EMAIL ERROR:", e)


# ================= SOC LOGIC =================

def predict_attack(packets, login_fail, sql):

    attack = "Normal"
    prob = 10

    if packets > 1500:
        attack = "DDoS"
        prob = 95

    elif packets > 800:
        attack = "DDoS"
        prob = 70

    elif login_fail == 1:
        attack = "BruteForce"
        prob = 80

    elif sql == 1:
        attack = "SQLInjection"
        prob = 90

    return attack, prob   # EXACTLY TWO VALUES


def severity_risk_mitre(attack):

    # High severity attacks
    if attack == "DDoS":
        return "High", 90, "T1499"

    if attack == "SQL Injection":
        return "High", 85, "T1190"

    # Medium
    if attack == "Brute Force":
        return "Medium", 60, "T1110"

    # Everything else = Low
    return "Low", 20, "N/A"
def attack_phase(attack):

    if attack=="DDoS":
        return "Execution"

    if attack=="BruteForce":
        return "Initial Access"

    if attack=="SQLInjection":
        return "Execution"

    return "Recon"



def geo_lookup(ip):

    print("[SOC] Geo lookup")

    try:
        r=requests.get(f"http://ip-api.com/json/{ip}").json()
        return r.get("country","Unknown")
    except:
        return "Unknown"

print("[SOC] Initializing database")
init_db()


def abuse_lookup(ip):

    print("[SOC] AbuseIPDB lookup")

    try:
        headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"

        r = requests.get(url, headers=headers).json()

        data = r["data"]

        return data["abuseConfidenceScore"], data["totalReports"]

    except:
        return 0,0


@app.route("/")
def dashboard():

    
    if "user" not in session:
        return redirect("/login")
    
    print("[SOC] Dashboard loaded")

    logs=fetch_logs()
    return render_template("dashboard.html",
                           logs=logs,
                           count=len(logs),
                           role=session["role"])


@app.route("/predict",methods=["POST"])
def predict():

    print("[SOC] New attack received")

    data=request.json

    packets=data["packets"]
    login_fail=data["login_fail"]
    sql=data["sql"]

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    print("[SOC] Attacker IP:",ip)

    country = data.get("country","Unknown")
    print("[SOC] Country:",country)

    attack, attack_prob = predict_attack(packets,login_fail,sql)
    print("[SOC DEBUG] attack =", attack)
    print("[SOC DEBUG] prob =", attack_prob)


    print("[SOC] Attack classified:",attack)

    severity,risk,mitre=severity_risk_mitre(attack)
    phase=attack_phase(attack)

    print("[SOC DEBUG] Attack:", attack)
    print("[SOC DEBUG] Severity:", severity)



    print("[SOC] Severity:",severity)
    print("[SOC] Risk:",risk)
    print("[SOC] MITRE:",mitre)

    abuse_score,reports = abuse_lookup(ip)

    print("[SOC] Abuse Score:",abuse_score)
    print("[SOC] Reports:",reports)

    insert_attack(ip,country,packets,login_fail,sql,
    attack,severity,risk,mitre,abuse_score,reports,attack_prob,phase)

    create_incident(attack,severity,risk,phase)


    global attack_counter
    attack_counter += 1
    print("[SOC] Attack counter:",attack_counter)


    print("[SOC] Attack logged to DB")

    body=f"""
SOC ALERT 🚨

Attack: {attack}
Severity: {severity}
Risk: {risk}
MITRE: {mitre}

IP: {ip}
Country: {country}
Packets: {packets}

CyberSecurity AI SOC
"""

    if attack != "Normal":
    # send_email("SOC ALERT", body)

     if os.name == "nt":
        block_ip(ip)




    return jsonify({
    "attack":attack,
    "severity":severity,
    "risk":risk,
    "mitre":mitre,
    "abuse_score":abuse_score,
    "reports":reports,
    "attack_prob": attack_prob

})


@app.route("/logs")
def logs():

    print("[SOC] Logs requested")

    return jsonify(fetch_logs())
# INCIDENT PAGE (HTML)
@app.route("/incidents")
def incidents():

    if "user" not in session:
        return redirect("/login")

    return render_template("incidents.html", role=session["role"])


# INCIDENT API (JSON)
@app.route("/api/incidents")
def api_incidents():

    conn = sqlite3.connect("/tmp/soc.db")

    c = conn.cursor()

    c.execute("SELECT * FROM incidents ORDER BY id DESC")
    rows = c.fetchall()

    conn.close()

    return jsonify(rows)


# CLOSE INCIDENT
@app.route("/close_incident/<int:iid>")
def close_incident(iid):

    # Only admin allowed
    if session.get("role") != "admin":
        return "Unauthorized", 403

    import sqlite3, datetime

    conn = sqlite3.connect("/tmp/soc.db")

    c = conn.cursor()

    c.execute("""
        UPDATE incidents
        SET status='Closed',
            closed_time=?
        WHERE id=?
    """,(datetime.datetime.now(), iid))

    # Audit log
    c.execute("""
        INSERT INTO audit(user, action, time)
        VALUES (?, ?, datetime('now'))
    """,(session["user"], f"Closed incident {iid}"))

    conn.commit()
    conn.close()

    return "ok"
@app.route("/attack_count")
def attack_count():
    return jsonify({"count":attack_counter})
init_db()

@app.route("/history")
def history():

    if "user" not in session:
        return redirect("/login")

    return render_template("history.html")

@app.route("/api/history")
def api_history():
    import sqlite3

    con = sqlite3.connect("/tmp/soc.db")

    cur = con.cursor()

    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 500")
    rows = cur.fetchall()

    con.close()
    return jsonify(rows)
# ASSIGN ANALYST + COMMENT
@app.route("/update_incident/<int:iid>", methods=["POST"])
def update_incident(iid):

    from flask import request
    import sqlite3

    analyst = request.form.get("analyst")
    comment = request.form.get("comment")

    conn = sqlite3.connect("/tmp/soc.db")

    c = conn.cursor()

    c.execute("""
        UPDATE incidents
        SET analyst=?, comment=?
        WHERE id=?
    """,(analyst,comment,iid))

    conn.commit()
    conn.close()

    return "ok"
app.secret_key = "socsecret"


@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        u = request.form["username"]
        p = request.form["password"]

        import sqlite3
        con = sqlite3.connect("/tmp/soc.db")

        c = con.cursor()

        c.execute("SELECT password, role FROM users WHERE username=?", (u,))
        r = c.fetchone()

        con.close()

        if r and check_password_hash(r[0], p):
            session["user"] = u
            session["role"] = r[1]
            return redirect("/")
        else:
            return "Invalid login"

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from flask import send_file, redirect
import datetime, sqlite3
@app.route("/testmail")
def testmail():
    send_email("SOC TEST", "This is a test email from your SOC system")
    return "Mail triggered"

@app.route("/report")
def report():

    if "user" not in session:
        return redirect("/login")

    con = sqlite3.connect("/tmp/soc.db")

    c = con.cursor()

    c.execute("SELECT ip,attack,severity,risk,time FROM logs ORDER BY id DESC LIMIT 25")
    logs = c.fetchall()
# ================= CHARTS =================

    os.makedirs("reports", exist_ok=True)

    severities = [l[2] for l in logs]
    sev_count = Counter(severities)

    plt.figure()
    plt.pie(sev_count.values(),
            labels=sev_count.keys(),
            autopct="%1.1f%%",
            colors=["red", "orange", "green"])
    plt.title("Severity Distribution")
    plt.savefig("reports/severity.png")
    plt.close()

    attacks = [l[1] for l in logs]
    atk_count = Counter(attacks)

    plt.figure(figsize=(6, 4))
    plt.bar(atk_count.keys(), atk_count.values())
    plt.xticks(rotation=30, ha="right")
    plt.title("Attack Types")
    plt.tight_layout()
    plt.savefig("reports/attacks.png")
    plt.close()

    # ================= INSIGHTS =================
    # ===== CRITICAL INCIDENTS =====
    critical = [l for l in logs if l[2]=="High" and l[3]>=80]
    critical_count = len(critical)
  
    ips = [l[0] for l in logs]
    risks = [(l[0], l[3]) for l in logs]

    top_attack = Counter(attacks).most_common(1)[0][0]
    top_ip = Counter(ips).most_common(1)[0][0]

    highest_risk_ip = max(risks, key=lambda x: x[1])[0]
    highest_risk_score = max(l[3] for l in logs)

    times = [l[4][:13] for l in logs]
    peak_time = Counter(times).most_common(1)[0][0]

    con.close()

    styles = getSampleStyleSheet()

    
    filename = os.path.join("reports","SOC_Report.pdf")


    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    
              

    elements=[]

    # ===== TITLE =====
    elements.append(Paragraph("""
<b>CyberSecurity AI SOC Platform</b><br/>
Incident Response Report<br/><br/>

Prepared By: Harshith Tadikonda<br/>
Environment: Demo SOC Lab<br/>
Report ID: SOC-""" + datetime.datetime.now().strftime("%Y%m%d%H%M") + """
""",styles["Title"]))

    elements.append(Paragraph(f"Generated: {datetime.datetime.now()}",styles["Normal"]))
    elements.append(Spacer(1,10))
    elements.append(Image("reports/severity.png", width=250, height=200))
    elements.append(Spacer(1,10))
    elements.append(Image("reports/attacks.png", width=300, height=200))
    elements.append(Spacer(1,15))

    elements.append(Paragraph(f"""
<b>Executive Insights</b><br/>

Top Attack Vector : {top_attack}<br/>
Most Active Attacker IP : {top_ip}<br/>
Highest Risk IP : {highest_risk_ip} (Risk {highest_risk_score})<br/>
Peak Attack Hour : {peak_time}<br/>
""", styles["Normal"]))

    elements.append(Paragraph(f"""
<b>Executive Summary</b><br/><br/>

Total Alerts: {len(logs)}<br/>
Critical Incidents: {critical_count}<br/>
Top Attack Type: {top_attack}<br/>
Top Attacker IP: {top_ip}<br/>
Highest Risk IP: {highest_risk_ip}<br/>
Highest Risk Score: {highest_risk_score}<br/>
Peak Attack Hour: {peak_time}<br/>
""", styles["Normal"]))


    elements.append(Spacer(1,12))


    

    # ===== TABLE =====
    table_data=[["IP Address","Attack Type","Severity","Risk","Timestamp"]]

    for l in logs:
        sev=l[2]
        badge=f"<font color='red'>High</font>" if sev=="High" else \
              f"<font color='orange'>Medium</font>" if sev=="Medium" else \
              f"<font color='green'>Low</font>"

        table_data.append([
            l[0],
            l[1],
            Paragraph(badge,styles["Normal"]),
            str(l[3]),
            l[4]
        ])

    table=Table(table_data,repeatRows=1,colWidths=[90,80,60,50,160])

    table.setStyle([

        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0f172a")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("FONT",(0,0),(-1,0),"Helvetica-Bold"),

        ("ALIGN",(0,0),(-1,0),"CENTER"),
        ("ALIGN",(2,1),(3,-1),"CENTER"),

        ("GRID",(0,0),(-1,-1),0.25,colors.grey),
        ("BOTTOMPADDING",(0,0),(-1,0),6),

        ("BACKGROUND",(0,1),(-1,-1),colors.whitesmoke)
    ])

    elements.append(table)

# ================= RECOMMENDATIONS =================
    elements.append(Spacer(1,15))

    elements.append(Paragraph(f"""
<b>Recommended Actions</b><br/><br/>

• Immediately block {highest_risk_ip}<br/>
• Investigate {critical_count} critical incidents<br/>
• Enable WAF protections for SQL Injection<br/>
• Increase firewall sensitivity for Port Scanning<br/>
• Monitor brute-force attempts for next 24 hours<br/>
• Review SOC alerts every 30 minutes<br/>
""",styles["Normal"]))




    elements.append(Spacer(1,15))

    elements.append(Paragraph("""
Generated by CyberSecurity AI SOC Engine<br/>
© 2026 CyberSecurity AI SOC
""",styles["Normal"]))

    doc.build(elements)


    return send_file(filename, as_attachment=True, download_name="SOC_Report.pdf")




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
