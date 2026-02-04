import os
from parsers.log_type_detector import detect_log_type

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(BASE_DIR, "uploads", "sample_auth.log")

log_type = detect_log_type(log_file)
print(f"Detected log type: {log_type}")
