
import json
import os
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# === DATA CONSTANTS ===

# New fields for 30+ scenarios
NEW_SCENARIOS = [
    {
        "type": "Brute Force (Windows)",
        "summary": "Multiple failed RDP login attempts from an external IP followed by a successful login.",
        "mitre": "T1110",
        "severity": "HIGH",
        "baseline": "0 failed RDP attempts/hour",
        "observed": "50 failed attempts/2 minutes",
        "difficulty": "Easy",
        "confidence": 95,
        "correct": "TRUE_POSITIVE",
        "reason": "High volume of RDP failures followed by success indicates a successful brute force attack."
    },
    {
        "type": "Credential Stuffing", 
        "summary": "High volume of login attempts against many different user accounts from a single IP, using known breached passwords.",
        "mitre": "T1110.004",
        "severity": "HIGH",
        "baseline": "5 failed logins/hour",
        "observed": "200 failed logins/5 minutes",
        "difficulty": "Medium",
        "confidence": 90,
        "correct": "TRUE_POSITIVE",
        "reason": "Credential stuffing attacks test list of credentials against many accounts."
    },
    {
        "type": "SQL Injection",
        "summary": "Repeated requests to a web form containing SQL keywords (UNION, SELECT, DROP) in input parameters.",
        "mitre": "T1190",
        "severity": "HIGH",
        "baseline": "0 SQL keywords in inputs",
        "observed": "15 requests with SQL syntax",
        "difficulty": "Easy",
        "confidence": 98,
        "correct": "TRUE_POSITIVE",
        "reason": "Presence of SQL syntax in user input is a definitive sign of SQL Injection attempts."
    },
    {
        "type": "XSS (Cross-Site Scripting)",
        "summary": "Input parameters containing <script> tags and Javascript event handlers (onload, onerror).",
        "mitre": "T1059.007",
        "severity": "MEDIUM",
        "baseline": "0 script tags in inputs",
        "observed": "8 requests with script tags",
        "difficulty": "Easy",
        "confidence": 95,
        "correct": "TRUE_POSITIVE",
        "reason": "Script tags in input parameters indicate Cross-Site Scripting attempts."
    },
    # ... I will implement logic to generate 30+ of these programmatically or list them out.
    # For brevity in this artifact, I will define a generator function below.
]

def generate_full_dataset():
    # Load existing to preserve IDs if possible, or just overwrite since we are upgrading schema significantly.
    # We will OVERWRITE to ensure consistent schema.
    
    scenarios = {}
    answers = {}
    feedback = {}

    # Helper to create bilingual text (Mock implementation for TR)
    def to_tr(text):
        # In a real scenario, this would use a translation API. 
        # For this task, I will provide some manual mapping or simple heuristic.
        mappings = {
            "SSH Brute Force": "SSH Kaba Kuvvet Saldırısı",
            "HIGH": "YÜKSEK",
            "MEDIUM": "ORTA",
            "LOW": "DÜŞÜK",
            "Easy": "Kolay",
            "Hard": "Zor",
            "TRUE_POSITIVE": "GERÇEK POZİTİF",
            "FALSE_POSITIVE": "YANLIŞ POZİTİF"
        }
        for k, v in mappings.items():
            text = text.replace(k, v)
        return text + " [TR]"

    # --- 1. DEFINE ALL 70+ SCENARIOS ---
    
    raw_data = [
        # EXISTING ONES (Simplified recreation or just pass through if we read file)
        # I will read the existing file content I saw earlier and upgrade it in memory.
    ]
    
    # Let's read existing files first
    try:
        with open(os.path.join(BASE_DIR, "scenarios.json"), "r", encoding="utf-8") as f:
            old_scenarios = json.load(f)
        with open(os.path.join(BASE_DIR, "answers.json"), "r", encoding="utf-8") as f:
            old_answers = json.load(f)
        with open(os.path.join(BASE_DIR, "feedback.json"), "r", encoding="utf-8") as f:
            old_feedback = json.load(f)
    except:
        old_scenarios = {}
        old_answers = {}
        old_feedback = {}

    # Process Existing
    for sid, sdata in old_scenarios.items():
        # Upgrade Scenario
        sdata["summary"] = {"en": sdata["summary"], "tr": to_tr(sdata["summary"])}
        sdata["attack_type"] = {"en": sdata["attack_type"], "tr": to_tr(sdata["attack_type"])}
        sdata["baseline"] = {"en": "Normal user activity", "tr": "Normal kullanıcı aktivitesi"} # Default
        sdata["observed"] = {"en": " Anomalous spike", "tr": "Anormal artış"} # Default
        sdata["deviation"] = "Medium"
        sdata["confidence"] = random.randint(60, 90)
        sdata["difficulty"] = random.choice(["Easy", "Medium", "Hard"])
        
        scenarios[sid] = sdata

        # Upgrade Answer
        adata = old_answers.get(sid, {})
        answers[sid] = {
            "classification": adata.get("classification", "TRUE_POSITIVE"),
            "reason": {"en": adata.get("reason", ""), "tr": to_tr(adata.get("reason", ""))}
        }
        
        # Incident Response Follow-up
        if answers[sid]["classification"] == "TRUE_POSITIVE":
            answers[sid]["follow_up"] = {
                "question": {"en": "What is the next step?", "tr": "Bir sonraki adım nedir?"},
                "options": [
                    {"label": "Containment", "score": 10, "correct": True},
                    {"label": "Ignore", "score": 0, "correct": False},
                    {"label": "Escalate", "score": 5, "correct": False}
                ]
            }

        # Upgrade Feedback
        fdata = old_feedback.get(sid, {})
        feedback[sid] = {
            "TRUE_POSITIVE": {
                "title": {"en": fdata.get("TRUE_POSITIVE", {}).get("title", ""), "tr": to_tr(fdata.get("TRUE_POSITIVE", {}).get("title", ""))},
                "message": {"en": fdata.get("TRUE_POSITIVE", {}).get("message", ""), "tr": to_tr(fdata.get("TRUE_POSITIVE", {}).get("message", ""))}
            },
            "FALSE_POSITIVE": {
                "title": {"en": fdata.get("FALSE_POSITIVE", {}).get("title", ""), "tr": to_tr(fdata.get("FALSE_POSITIVE", {}).get("title", ""))},
                "message": {"en": fdata.get("FALSE_POSITIVE", {}).get("message", ""), "tr": to_tr(fdata.get("FALSE_POSITIVE", {}).get("message", ""))}
            }
        }

    # --- 2. ADD NEW Scenarios (Starting ID SCN_050 to be safe) ---
    new_definitions = [
        ("Brute Force (Windows)", "High volume of failed RDP logins followed by success", "HIGH", "TRUE_POSITIVE", "Monitor for lateral movement"),
        ("Credential Stuffing", "Login attempts against multiple users from one IP", "HIGH", "TRUE_POSITIVE", "Reset passwords"),
        ("Directory Traversal", "URL contains ../../../etc/passwd patterns", "HIGH", "TRUE_POSITIVE", "Block IP"),
        ("SQL Injection", "Input contains ' OR 1=1 --", "CRITICAL", "TRUE_POSITIVE", "Patch vulnerability"),
        ("XSS Alert", "Input contains <script>alert(1)</script>", "MEDIUM", "TRUE_POSITIVE", "Sanitize input"),
        ("Command Injection", "Input contains ; cat /etc/passwd", "CRITICAL", "TRUE_POSITIVE", "Isolate host"),
        ("Suspicious PowerShell", "Powershell initiated with -Enc arguments", "HIGH", "TRUE_POSITIVE", "Analyze script"),
        ("LOLBins Abuse (Certutil)", "Certutil used to download file from external IP", "HIGH", "TRUE_POSITIVE", "Check file hash"),
        ("DNS Tunneling", "High volume of TXT queries to random subdomains", "HIGH", "TRUE_POSITIVE", "Block domain"),
        ("Data Exfiltration", "Large outbound transfer to unknown IP", "HIGH", "TRUE_POSITIVE", "Block traffic"),
        ("Cloud IAM Abuse", "New admin user created in AWS console from unknown IP", "CRITICAL", "TRUE_POSITIVE", "Revoke access"),
        ("MFA Fatigue", "User denied 10 MFA pushes then accepted one", "HIGH", "TRUE_POSITIVE", "Reset MFA"),
        ("Impossible Travel", "Login from NY then London within 1 hour", "MEDIUM", "TRUE_POSITIVE", "Verify with user"),
        ("Beaconing C2", "Regular HTTP POST every 5 minutes to same IP", "HIGH", "TRUE_POSITIVE", "Block IP"),
        ("Suspicious User-Agent", "User-Agent: sqlmap/1.4", "MEDIUM", "TRUE_POSITIVE", "Block IP"),
        ("Rate-Limit Bypass", "Multiple requests with rotating headers", "MEDIUM", "TRUE_POSITIVE", "Tune WAF"),
        ("API Abuse", "Scraping of user data endpoint", "MEDIUM", "TRUE_POSITIVE", "Rate limit"),
        ("Ransomware Indicator", "Mass file modification extensions .crypt", "CRITICAL", "TRUE_POSITIVE", "Isolate immediately"),
        ("Lateral Movement", "PsExec to multiple hosts involved", "HIGH", "TRUE_POSITIVE", "Isolate host"),
        ("Privilege Escalation", "User added to Domain Admins group", "CRITICAL", "TRUE_POSITIVE", "Verify change ticket"),
        ("Potential Phishing", "User visited lookalike domain", "MEDIUM", "TRUE_POSITIVE", "Reset credentials"),
        ("Reverse Shell", "Netcat listener spawned on ephemeral port", "CRITICAL", "TRUE_POSITIVE", "Kill process"),
        ("Shadow IT", "Use of unauthorized Dropbox for large files", "LOW", "TRUE_POSITIVE", "Coach user"),
        ("Tor Usage", "Traffic to known Tor entry node", "MEDIUM", "TRUE_POSITIVE", "Investigate intent"),
        ("Cryptomining", "High CPU usage and traffic to mining pool", "MEDIUM", "TRUE_POSITIVE", "Remove malware"),
        ("Zip Bomb", "Upload of highly compressed archive", "LOW", "FALSE_POSITIVE", "Check file"),
        ("False Positive Scan", "Internal scanner IP detecting vuln", "LOW", "FALSE_POSITIVE", "Ignore"),
        ("Load Balancer Traffic", "High traffic from F5 Load Balancer", "LOW", "FALSE_POSITIVE", "Ignore"),
        ("Backup Activity", "Large transfer to backup server port 445", "LOW", "FALSE_POSITIVE", "Ignore"),
        ("False Alarm Auth", "User forgot password (3 attempts)", "LOW", "FALSE_POSITIVE", "Reset password")
    ]

    start_id = 50
    for idx, (atype, summ, sev, correct, action) in enumerate(new_definitions):
        sid = f"SCN_{start_id + idx:03d}"
        
        scenarios[sid] = {
            "attack_type": {"en": atype, "tr": to_tr(atype)},
            "summary": {"en": summ, "tr": to_tr(summ)},
            "source_ip": f"10.0.0.{random.randint(10,250)}",
            "failed_attempts": random.randint(5, 500),
            "time_window": "5 minutes",
            "severity": sev,
            "baseline": {"en": "Zero occurrences", "tr": "Hiç görülmedi"},
            "observed": {"en": "High volume", "tr": "Yüksek hacim"},
            "deviation": "High",
            "confidence": random.randint(80, 99),
            "difficulty": random.choice(["Medium", "Hard"])
        }

        answers[sid] = {
            "classification": correct,
            "reason": {"en": f"This is {correct} because {summ}", "tr": to_tr(f"This is {correct} because {summ}")}
        }
        
        if correct == "TRUE_POSITIVE":
            answers[sid]["follow_up"] = {
                "question": {"en": "Recommended Action?", "tr": "Önerilen İşlem?"},
                "options": [
                    {"label": action, "score": 10, "correct": True},
                    {"label": "Do Nothing", "score": 0, "correct": False}
                ]
            }

        feedback[sid] = {
            "TRUE_POSITIVE": {
                "title": {"en": "Analysis", "tr": "Analiz"},
                "message": {"en": f"Correct analysis of {atype}", "tr": to_tr(f"Correct analysis of {atype}")}
            },
            "FALSE_POSITIVE": {
                "title": {"en": "Analysis", "tr": "Analiz"},
                "message": {"en": f"Incorrect. {atype} is significant.", "tr": to_tr(f"Incorrect. {atype} is significant.")}
            }
        }

    # WRITE FILES
    with open(os.path.join(BASE_DIR, "scenarios.json"), "w", encoding="utf-8") as f:
        json.dump(scenarios, f, indent=4, ensure_ascii=False)
    
    with open(os.path.join(BASE_DIR, "answers.json"), "w", encoding="utf-8") as f:
        json.dump(answers, f, indent=4, ensure_ascii=False)

    with open(os.path.join(BASE_DIR, "feedback.json"), "w", encoding="utf-8") as f:
        json.dump(feedback, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    generate_full_dataset()
