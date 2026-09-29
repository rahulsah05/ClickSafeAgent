import random
import pandas as pd

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.in", "wikipedia.org",
    "instagram.com", "microsoft.com", "apple.com", "flipkart.com"
]

PHISHING_KEYWORDS = [
    "login", "verify", "update", "reset", "secure", "account", "payment"
]

PHISHING_TLDS = ["xyz", "top", "info", "online", "icu", "shop"]

def generate_benign(n=50000):
    data = []
    for _ in range(n):
        dom = random.choice(BENIGN_DOMAINS)
        url = f"https://{dom}/{random.randint(1,9999)}"
        data.append([url, "good"])
    return data

def generate_phishing(n=50000):
    data = []
    for _ in range(n):
        brand = random.choice(BENIGN_DOMAINS).split(".")[0]
        keyword = random.choice(PHISHING_KEYWORDS)
        tld = random.choice(PHISHING_TLDS)

        url = f"http://{keyword}-{brand}-{random.randint(100,999)}.{tld}/security"

        data.append([url, "bad"])
    return data

benign = generate_benign(50000)
phish = generate_phishing(50000)

df = pd.DataFrame(benign + phish, columns=["url", "label"])

df.to_csv("synthetic_dataset.csv", index=False)
print("Dataset created: synthetic_dataset.csv")
