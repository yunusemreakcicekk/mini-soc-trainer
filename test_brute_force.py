import os
from parsers.linux_auth import parse_linux_auth_log
from detection.brute_force import detect_brute_force

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(BASE_DIR, "uploads", "sample_auth.log")

events = parse_linux_auth_log(log_file)
alerts = detect_brute_force(events)

print(f"Parsed {len(events)} events")
print(f"Detected {len(alerts)} alerts")

for alert in alerts:
    print("\n🚨 ALERT DETECTED")
    print(f"Attack Type: {alert['attack_type']}")
    print(f"MITRE: {alert['mitre']}")
    print(f"Severity: {alert['severity']}")
    print(f"Source IP: {alert['source_ip']}")
    print(f"Failed Attempts: {alert['failed_attempts']}")
    print(f"Reason: {alert['reason']}")
    print("Recommended SOC Actions:")
    for action in alert["analyst_action"]:
        print(f" - {action}")
