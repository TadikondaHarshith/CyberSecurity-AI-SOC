import sqlite3

DB_NAME = "/tmp/soc.db"

# ---------------- INIT DATABASE ----------------

def init_db():
    conn = sqlite3.connect("/tmp/soc.db")
    c = conn.cursor()

    # USERS
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT
    )
    """)

    # LOGS
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        country TEXT,
        packets INTEGER,
        login_fail INTEGER,
        sql INTEGER,
        attack TEXT,
        severity TEXT,
        risk INTEGER,
        mitre TEXT,
        abuse INTEGER,
        reports INTEGER,
        phase TEXT,
        time TEXT
    )
    """)

    # INCIDENTS
    c.execute("""
    CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack TEXT,
        severity TEXT,
        risk INTEGER,
        phase TEXT,
        status TEXT DEFAULT 'Open',
        analyst TEXT,
        comment TEXT,
        time TEXT,
        closed_time TEXT
    )
    """)

    conn.commit()
    conn.close()



# ---------------- INSERT ATTACK ----------------

def insert_attack(ip,country,packets,login_fail,sql,
                  attack,severity,risk,mitre,
                  abuse,reports,attack_prob,phase):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs(
        ip,country,packets,login_fail,sql,
        attack,severity,risk,mitre,
        abuse,reports,attack_prob,phase
    )
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
    """,(ip,country,packets,login_fail,sql,
         attack,severity,risk,mitre,
         abuse,reports,attack_prob,phase))

    conn.commit()
    conn.close()


# ---------------- FETCH LOGS ----------------

def fetch_logs():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY id DESC")

    rows = cursor.fetchall()
    conn.close()

    return rows


def create_incident(attack,severity,risk,phase):

    conn=sqlite3.connect(DB_NAME)
    c=conn.cursor()

    c.execute("""
    INSERT INTO incidents(attack,severity,risk,phase,time)
    VALUES(?,?,?,?,datetime('now'))
    """,(attack,severity,risk,phase))

    conn.commit()
    conn.close()



# ---------------- SAVE BLOCKED IP ----------------

def save_block(ip):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO blocked_ips(ip)
    VALUES(?)
    """,(ip,))


    conn.commit()
    conn.close()
