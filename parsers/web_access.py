import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<date>\d+/\w+/\d+:\d+:\d+:\d+)(?: [+\-]\d{4})?\] "(?P<method>GET|POST) (?P<path>.*?) HTTP[^"]*" (?P<status>\d{3})'
)

def parse_web_access_log(file_path):
    events = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            match = LOG_PATTERN.search(line)
            if match:
                events.append({
                    "timestamp": parse_time(match.group("date")),
                    "event": "HTTP_REQUEST",
                    "ip": match.group("ip"),
                    "path": str(match.group("path")),
                    "method": match.group("method"),
                    "status": int(match.group("status"))
                })

    return events

def parse_time(timestr):
    # Örnek: 22/Jan/2026:11:01:10
    return datetime.strptime(timestr, "%d/%b/%Y:%H:%M:%S")
