import requests
import random
import time

URL = "https://cybersecurity-ai-soc.onrender.com/predict"


countries = [
    "India","USA","Germany","Russia","China","Brazil","France","UK"
]

while True:

    data = {
        "packets": random.randint(300,2500),
        "login_fail": random.randint(0,1),
        "sql": random.randint(0,1),
    }

    headers = {
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    }

    r = requests.post(URL, json=data, headers=headers)

    print("Injected:", data)

    time.sleep(3)
