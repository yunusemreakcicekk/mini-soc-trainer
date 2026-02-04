from parsers.linux_auth import parse_linux_auth_log
with open('uploads/sample_auth.log', 'r') as f:
    lines = f.readlines()
    print(f"Lines in file: {len(lines)}")
    for line in lines:
        print(repr(line))
events = parse_linux_auth_log('uploads/sample_auth.log')
print(f"Parsed {len(events)} events")
for e in events:
    print(e)