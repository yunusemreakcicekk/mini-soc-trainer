import os
from parsers.linux_auth import parse_linux_auth_log

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(BASE_DIR, "uploads", "sample_auth.log")

events = parse_linux_auth_log(log_file)

for event in events:
    print(event)
