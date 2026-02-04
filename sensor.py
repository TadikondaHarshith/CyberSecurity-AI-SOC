from scapy.all import sniff, IP, TCP
import requests
import time

SOC_URL="http://127.0.0.1:5000/predict"


packet_count=0
login_fail=0
sql_flag=0

last_sent=0

print("[IDS] Live IDS started")

def analyze(pkt):

    global packet_count,login_fail,sql_flag,last_sent

    if IP in pkt and TCP in pkt:

        packet_count+=1

        dport=pkt[TCP].dport

        if dport==22 or dport==3389:
            login_fail+=1

        payload=str(pkt.payload)

        if "select" in payload.lower() or "union" in payload.lower():
            sql_flag=1

    now=time.time()

    # SEND AT MOST ONCE EVERY 6 SECONDS
    if now-last_sent>6:

        if packet_count>50 or login_fail>3 or sql_flag==1:

            data={
                "packets":packet_count,
                "login_fail":login_fail,
                "sql":sql_flag
            }

            try:
                print("[IDS] Sending traffic to SOC")

                requests.post(SOC_URL,json=data)

                last_sent=now

            except:
                pass

            packet_count=0
            login_fail=0
            sql_flag=0

sniff(prn=analyze,store=False)
