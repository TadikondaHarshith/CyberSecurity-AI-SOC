from scapy.all import sniff, IP, TCP
import requests
import time

SOC_URL="http://127.0.0.1:5000/predict"

packet_count=0
login_fail=0
sql_flag=0
last_sent=0

print("[IDS] Live IDS started - sniffing traffic...")

def analyze(pkt):

    global packet_count,login_fail,sql_flag,last_sent

    print(".", end="", flush=True)

    if IP in pkt and TCP in pkt:

        packet_count+=1

        dport=pkt[TCP].dport

        if dport==22 or dport==3389:
            login_fail+=1

        payload=str(bytes(pkt[TCP].payload))

        if "select" in payload.lower() or "union" in payload.lower():
            sql_flag=1

    now=time.time()

    if now-last_sent>5:

        data={
            "packets":packet_count,
            "login_fail":login_fail,
            "sql":sql_flag
        }

        try:
            print("\n[IDS] Sending:",data)
            requests.post(SOC_URL,json=data,timeout=3)
            last_sent=now
        except Exception as e:
            print("SOC unreachable",e)

        packet_count=0
        login_fail=0
        sql_flag=0

sniff(filter="tcp",prn=analyze,store=False)
