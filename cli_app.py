import os
from parsers.log_type_detector import detect_log_type
from parsers.linux_auth import parse_linux_auth_log
from detection.brute_force import detect_brute_force
from parsers.web_access import parse_web_access_log
from detection.web_recon import detect_web_recon



def print_header():
    print("=" * 60)
    print(" MINI SOC TRAINER - LOG ANALYSIS REPORT")
    print("=" * 60)


def print_alert(alert):
    print("\n🚨 ALERT DETECTED")
    print(f"Attack Type : {alert['attack_type']}")
    print(f"MITRE       : {alert['mitre']}")
    print(f"Severity    : {alert['severity']}")
    print(f"Source IP   : {alert['source_ip']}")
    print(f"Attempts    : {alert['failed_attempts']}")
    print(f"Time Window : {alert['time_window']}")

    explanation = alert.get("explanation", {})
    if explanation:
        print("\n🔍 Why was this alert generated?")
        print(f"- {explanation.get('why_detected')}")

        print("\n📘 Severity Explanation")
        print(f"- {explanation.get('severity_meaning')}")

        print("\n🎓 Learning Note")
        print(f"- {explanation.get('learning_note')}")

    print("\n🧑‍💻 Recommended SOC Actions")
    for action in alert.get("analyst_action", []):
        print(f"- {action}")



def analyze_log(file_path):
    log_type = detect_log_type(file_path)

    print(f"\n📂 Detected Log Type: {log_type}")

    if log_type == "linux_auth":
        events = parse_linux_auth_log(file_path)
        print(f"Parsed {len(events)} events")

        alerts = detect_brute_force(events)
        return alerts

    elif log_type == "web_access":
        events = parse_web_access_log(file_path)
        print(f"Parsed {len(events)} events")

        alerts = detect_web_recon(events)
        print(">>> WEB ACCESS ANALYSIS STARTED")

        return alerts

    else:
        print("⚠️ This log type is not supported yet.")
        return []




def main():
    print_header()

    log_path = input("\nEnter path to log file: ").strip()

    if not os.path.exists(log_path):
        print("❌ File not found.")
        return

    alerts = analyze_log(log_path)

    if not alerts:
        print("\n✅ No security alerts detected.")
    else:
        print(f"\nDetected {len(alerts)} alert(s).")
        for alert in alerts:
            print_alert(alert)


if __name__ == "__main__":
    main()
