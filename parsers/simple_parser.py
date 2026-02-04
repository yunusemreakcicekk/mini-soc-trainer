import re

def parse_simple_log(file_path):
    """
    Parses logs into a list of generic event dictionaries.
    Returns: [{'line': str, 'timestamp': str, 'raw': str, ...extracted...}]
    """
    events = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            event = {"raw": line}
            
            # Simple Timestamp Extraction (YYYY-MM-DD HH:MM:SS)
            ts_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
            if ts_match:
                event["timestamp"] = ts_match.group(0)
            
            # Key=Value Extraction (e.g., user=ahmet)
            kv_pairs = re.findall(r"(\w+)=([^\s]+)", line)
            for k, v in kv_pairs:
                event[k] = v

            events.append(event)
    return events
