import re
from datetime import datetime

FAILED_PATTERN = re.compile(
    r"(?P<date>\w+ \d+ \d+:\d+:\d+).*sshd.*Failed password for (?:invalid user |user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

SUCCESS_PATTERN = re.compile(
    r"(?P<date>\w+ \d+ \d+:\d+:\d+).*sshd.*Accepted password for (?:user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def parse_linux_auth_log(file_path):
    events = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            failed = FAILED_PATTERN.search(line)
            success = SUCCESS_PATTERN.search(line)

            if failed:
                events.append({
                    "timestamp": parse_time(failed.group("date")),
                    "event": "FAILED_LOGIN",
                    "user": failed.group("user"),
                    "ip": failed.group("ip"),
                    "service": "ssh"
                })

            elif success:
                events.append({
                    "timestamp": parse_time(success.group("date")),
                    "event": "SUCCESS_LOGIN",
                    "user": success.group("user"),
                    "ip": success.group("ip"),
                    "service": "ssh"
                })

    return events

def parse_time(timestr):
    return datetime.strptime(timestr, "%b %d %H:%M:%S").replace(year=2026)
