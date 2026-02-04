from collections import defaultdict
from datetime import timedelta
import json
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_education():
    with open(os.path.join(BASE_DIR, "education", "attack_explanations.json"), "r", encoding="utf-8") as f:
        attack_explanations = json.load(f)

    with open(os.path.join(BASE_DIR, "education", "severity_guide.json"), "r", encoding="utf-8") as f:
        severity_guide = json.load(f)

    with open(os.path.join(BASE_DIR, "education", "analyst_actions.json"), "r", encoding="utf-8") as f:
        analyst_actions = json.load(f)

    return attack_explanations, severity_guide, analyst_actions


TIME_WINDOW = timedelta(minutes=1)

def detect_brute_force(events):
    alerts = []
    benign_reason = None
    
    # Filter for failed and success login events
    failed_events = [e for e in events if e["event"] == "FAILED_LOGIN"]
    success_events = [e for e in events if e["event"] == "SUCCESS_LOGIN"]

    ip_events = defaultdict(list)
    for e in failed_events:
        ip_events[e["ip"]].append(e["timestamp"])

    # Brute Force Detection
    for ip, times in ip_events.items():
        times.sort()
        for i in range(len(times)):
            # Check for X attempts in 1 minute
            window = [t for t in times if times[i] <= t <= times[i] + TIME_WINDOW]
            count = len(window)

            # Threshold: >= 3
            if count >= 3:
                alerts.append({
                    "attack_type": "SSH Brute Force Attempt",
                    "mitre": "T1110.001 – Brute Force: Password Guessing",
                    "severity": "MEDIUM",
                    "source_ip": ip,
                    "failed_attempts": count,
                    "time_window": f"{int((window[-1] - window[0]).total_seconds()) + 1} seconds" if len(window) > 1 else "Instant",
                    
                    "fields": {
                        "lbl_target_service": "SSH",
                        "lbl_failed_login_attempts": count
                    },

                    "explanation": {
                        "why_detected": {
                            "en": "Multiple failed SSH authentication attempts for different invalid usernames were observed from the same external IP address within a very short time window, indicating automated password guessing activity.",
                            "tr": "Aynı harici IP adresinden çok kısa bir zaman penceresinde farklı geçersiz kullanıcı adları için birden fazla başarısız SSH kimlik doğrulama denemesi gözlemlendi, bu da otomatik parola tahmin aktivitesini gösterir."
                        },
                        "severity_meaning": {
                            "en": "**MEDIUM** severity indicates active reconnaissance or brute-force attempts against exposed services. While no successful authentication occurred, continued attempts may lead to compromise if not mitigated.",
                            "tr": "**ORTA** önem derecesi, maruz kalan servislere karşı aktif keşif veya kaba kuvvet girişimlerini gösterir. Başarılı bir kimlik doğrulama gerçekleşmemiş olsa da, azaltılmazsa devam eden girişimler ele geçirilmeye yol açabilir."
                        },
                        "learning_note": {
                            "en": "Attackers often attempt common usernames such as root, admin, or oracle during SSH brute-force attacks. Rapid failures across multiple usernames are a strong indicator of automated tools.",
                            "tr": "Saldırganlar, SSH kaba kuvvet saldırıları sırasında genellikle root, admin veya oracle gibi yaygın kullanıcı adlarını denerler. Birden fazla kullanıcı adında hızlı başarısızlıklar, otomatik araçların güçlü bir göstergesidir."
                        }
                    },

                    "recommended_actions": [
                        "action_block_source_ip",
                        "action_ssh_key_auth",
                        "action_review_ssh_exposure",
                        "action_monitor_escalation",
                        "action_hunt_lateral"
                    ]
                }) 
                break # Avoid duplicate alerts for same IP window

    # Benign User Typo Detection (If no alerts found)
    if not alerts and len(failed_events) > 0 and len(success_events) > 0:
        # Check if we have failures followed by success for the same user/ip
        # Heuristic: If we have failures and at least one success from same IP?
        # Or specifically check timestamps? 
        # For this lab/task, simple existence of both failure and success for same user/ip is strong indicator.
        
        # Group by user + IP
        typo_candidates = defaultdict(lambda: {"fail": 0, "success": 0})
        
        for e in failed_events:
            key = (e.get("user"), e.get("ip"))
            typo_candidates[key]["fail"] += 1
            
        for e in success_events:
            key = (e.get("user"), e.get("ip"))
            if key in typo_candidates:
                 typo_candidates[key]["success"] += 1
        
        # If any user has fails AND success
        for (user, ip), counts in typo_candidates.items():
            if counts["fail"] > 0 and counts["success"] > 0:
                benign_reason = "ℹ️ Informational: Multiple failed logins followed by a successful authentication from the same internal IP likely indicate a user mistyping their password."
                break

    return alerts, benign_reason
