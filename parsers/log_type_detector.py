def detect_log_type(file_path):
    with open(file_path, "r", errors="ignore") as f:
        sample = f.read(3000)

    if "Failed password for" in sample and "sshd" in sample:
        return "linux_auth"

    if "EventID" in sample and "4625" in sample:
        return "windows_security"

    if "powershell.exe" in sample:
        return "windows_powershell"

    if "MFA_Push_" in sample:
        return "cloud_mfa"

    if "user=" in sample and "location=" in sample:
        return "azure_ad"

    if "action=upload" in sample and "destination=" in sample:
        return "cloud_upload"

    if "query A" in sample:
        return "dns_traffic"

    if "TCP SYN" in sample:
        return "network_traffic"

    if "SMB Auth Failure" in sample:
        return "windows_smb"

    if "\"event_type\"" in sample and "alert" in sample:
        return "suricata"
    
    if "python-requests" in sample:
        return "suspicious_user_agent"

    if "HTTP/1.1" in sample and ("GET" in sample or "POST" in sample):
        return "web_access"

    return "unknown"
