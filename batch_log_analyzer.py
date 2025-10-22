import os
import re
import pandas as pd
import matplotlib.pyplot as plt

# === CONFIGURATION ===
LOG_FOLDER = "./logs"  # Folder containing your log files
OUTPUT_FILE = "combined_cybersecurity_report.csv"

# === LOG PARSING FUNCTION ===
def parse_log_file(filepath):
    pattern = r"(?P<Timestamp>\S+ \S+) - IP: (?P<IP_Address>[\d\.]+) - User: (?P<User>\S+) - Action: (?P<Action>.+)"
    entries = []
    with open(filepath, "r") as file:
        for line in file:
            match = re.match(pattern, line.strip())
            if match:
                entry = match.groupdict()
                entry["Source File"] = os.path.basename(filepath)
                entries.append(entry)
    return entries

# === RISK CLASSIFICATION FUNCTION ===
def assign_risk(action):
    a = action.lower()
    if any(k in a for k in ["port request", "outbound data", "transfer", "exfiltration", "attack"]):
        return "High"
    elif any(k in a for k in ["unusual", "failed login", "multiple login", "timeout"]):
        return "Medium"
    elif "successful" in a:
        return "Low"
    else:
        return "Unknown"

# === PROCESS ALL FILES ===
all_entries = []
for file in os.listdir(LOG_FOLDER):
    if file.endswith(".txt"):
        filepath = os.path.join(LOG_FOLDER, file)
        print(f"🔍 Processing: {filepath}")
        all_entries.extend(parse_log_file(filepath))

df = pd.DataFrame(all_entries)

if df.empty:
    print("⚠️ No log entries found. Please check your folder path or file format.")
else:
    df["Risk Level"] = df["Action"].apply(assign_risk)

    # === SAVE COMBINED REPORT ===
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"✅ Combined report saved as: {OUTPUT_FILE}")

    # === VISUALIZE ===
    plt.figure(figsize=(6,4))
    df["Risk Level"].value_counts().plot(kind="bar", title="Risk Level Distribution Across All Logs")
    plt.xlabel("Risk Level")
    plt.ylabel("Count")
    plt.show()

    plt.figure(figsize=(6,4))
    df["User"].value_counts().plot(kind="bar", title="Actions per User Across All Logs")
    plt.xlabel("User")
    plt.ylabel("Count")
    plt.show()
