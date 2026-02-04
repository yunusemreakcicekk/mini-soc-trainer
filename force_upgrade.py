
import json
import os
import random
import sys

# Force output to file directly to avoid redirection issues
LOG_FILE = "force_upgrade.log"

def log(msg):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")
    print(msg)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(BASE_DIR, "training_lab")

log(f"Starting Force Upgrade in {TARGET_DIR}")

def to_tr(text):
    if not isinstance(text, str): return str(text)
    mappings = {
        "SSH Brute Force": "SSH Kaba Kuvvet Saldırı",
        "HIGH": "YÜKSEK", 
        "MEDIUM": "ORTA",
        "LOW": "DÜŞÜK",
        "TRUE_POSITIVE": "GERÇEK POZİTİF",
        "FALSE_POSITIVE": "YANLIŞ POZİTİF"
    }
    for k, v in mappings.items():
        text = text.replace(k, v)
    return text + " [TR]"

try:
    scenarios_path = os.path.join(TARGET_DIR, "scenarios.json")
    answers_path = os.path.join(TARGET_DIR, "answers.json")
    feedback_path = os.path.join(TARGET_DIR, "feedback.json")

    with open(scenarios_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)
    with open(answers_path, "r", encoding="utf-8") as f:
        answers = json.load(f)
    with open(feedback_path, "r", encoding="utf-8") as f:
        feedback = json.load(f)

    log(f"Loaded {len(scenarios)} scenarios.")

    count = 0
    for sid, sdata in scenarios.items():
        # Always ensure fields exist
        if "baseline" not in sdata:
            sdata["baseline"] = {"en": "Normal user activity", "tr": "Normal kullanıcı aktivitesi"}
        if "observed" not in sdata:
            sdata["observed"] = {"en": "Anomalous spike", "tr": "Anormal artış"}
        if "deviation" not in sdata:
            sdata["deviation"] = "Medium"
        if "confidence" not in sdata:
            sdata["confidence"] = random.randint(60, 95)
        if "difficulty" not in sdata:
            sdata["difficulty"] = random.choice(["Easy", "Medium", "Hard"])

        # Ensure Bilingual Summary
        if isinstance(sdata["summary"], str):
            sdata["summary"] = {"en": sdata["summary"], "tr": to_tr(sdata["summary"])}
        
        # Ensure Bilingual Attack Type
        if isinstance(sdata["attack_type"], str):
            sdata["attack_type"] = {"en": sdata["attack_type"], "tr": to_tr(sdata["attack_type"])}

        scenarios[sid] = sdata
        count += 1

    log(f"Updated {count} scenarios.")

    # Save
    with open(scenarios_path, "w", encoding="utf-8") as f:
        json.dump(scenarios, f, indent=4, ensure_ascii=False)
    
    log("Saved scenarios.json")

except Exception as e:
    log(f"ERROR: {e}")
