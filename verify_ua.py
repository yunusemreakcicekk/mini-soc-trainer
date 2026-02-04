
import sys
import os
import json
import traceback

sys.path.append(os.getcwd())

output_file = "verify_output_ua.txt"

try:
    from parsers.simple_parser import parse_simple_log
    from detection.simple_rules import detect_simple_threats

    log_file = os.path.join("training_logs", "suspicious_user_agent.log")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("--- Testing Suspicious UA Log ---\n")
        if os.path.exists(log_file):
                # Test Auto-Detection
                from parsers.log_type_detector import detect_log_type
                detected_type = detect_log_type(log_file)
                print(f"Detected Log Type: {detected_type}")
                f.write(f"Detected Log Type: {detected_type}\n")

                events = parse_simple_log(log_file)
                print(f"Events Parsed: {len(events)}")
                f.write(f"Events Parsed: {len(events)}\n")
                
                # Manual trigger of specific log type
                alerts, benign = detect_simple_threats(events, "suspicious_user_agent")
                
                f.write(f"Alerts Found: {len(alerts)}\n")
                for alert in alerts:
                    f.write(json.dumps(alert, indent=4) + "\n")
                
            except Exception as e:
                f.write(f"Error processing log: {e}\n")
                f.write(traceback.format_exc())
        else:
            f.write(f"Log not found: {os.path.abspath(log_file)}\n")

except Exception as e:
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"Critical Error: {e}\n")
        f.write(traceback.format_exc())
