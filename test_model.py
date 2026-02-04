import joblib

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

    return attack, prob   # ONLY TWO VALUES

joblib.dump(predict_attack, "model.pkl")

print("MODEL REBUILT")
