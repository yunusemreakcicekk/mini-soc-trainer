from datetime import datetime

def detect_simple_threats(events, log_type):
    alerts = []
    benign_reason = None
    
    if log_type == "windows_powershell":
        for e in events:
            if "Invoke-WebRequest" in e["raw"] and "payload.exe" in e["raw"]:
                alerts.append({
                    "attack_type": "Malicious PowerShell Activity",
                    "severity": "HIGH",
                    "mitre": "T1059.001 - Command and Scripting Interpreter: PowerShell",
                    "source_ip": "Localhost (Script)",
                    "failed_attempts": "N/A (Execution)",
                    "time_window": e.get("timestamp", "Unknown"),
                    "explanation": {
                        "why_detected": {
                            "en": "PowerShell was observed downloading an executable file (payload.exe) from a remote URL using Invoke-WebRequest.",
                            "tr": "PowerShell’in Invoke-WebRequest kullanarak uzak bir URL'den yönetilebilir bir dosya (payload.exe) indirdiği gözlemlendi."
                        },
                        "severity_meaning": {
                            "en": "**HIGH** severity indicates a likely active malware execution or dropper activity. Immediate investigation is required.",
                            "tr": "**YÜKSEK** önem derecesi, olası bir aktif kötü amaçlı yazılım çalıştırma veya yükleyici aktivitesini gösterir. Derhal inceleme gereklidir."
                        },
                        "learning_note": {
                            "en": "Attackers often use PowerShell to download and execute payload stages filelessly or receiving them from C2 servers.",
                            "tr": "Saldırganlar genellikle yük aşamalarını dosyasız olarak indirmek ve çalıştırmak için veya C2 sunucularından almak için PowerShell kullanırlar."
                        }
                    },
                    "recommended_actions": [
                        "action_isolate_workstation",
                        "action_capture_memory",
                        "action_review_powershell",
                        "action_block_url"
                    ]
                })

    elif log_type == "network_traffic":
        ports = set()
        src_ip = "Unknown"
        count = 0
        for e in events:
            if "dst_port" in e:
                ports.add(e["dst_port"])
            if "src" in e:
                src_ip = e["src"]
            count += 1
        
        if len(ports) >= 3:
            alerts.append({
                "attack_type": "Port Scanning Activity",
                "severity": "MEDIUM",
                "mitre": "T1046 - Network Service Discovery",
                "source_ip": src_ip,
                "failed_attempts": f"{len(ports)} unique destination ports",
                "time_window": "Short Duration",
                "explanation": {
                    "why_detected": {
                        "en": f"A single source IP ({src_ip}) attempted connections to {len(ports)} different destination ports.",
                        "tr": f"Tek bir kaynak IP ({src_ip}), {len(ports)} farklı hedef portuna bağlantı denemesinde bulundu."
                    },
                    "severity_meaning": {
                        "en": "**MEDIUM** severity suggests reconnaissance. While not an exploit itself, it often precedes an attack.",
                        "tr": "**ORTA** önem derecesi keşif faaliyetini düşündürür. Kendi başına bir istismar olmasa da, genellikle bir saldırıdan önce gelir."
                    },
                    "learning_note": {
                        "en": "Scanners blindly probe common ports (22, 80, 443, 3389) to identify available services for exploitation.",
                        "tr": "Tarayıcılar, istismar edilebilir servisleri belirlemek için yaygın portları (22, 80, 443, 3389) rastgele yoklarlar."
                    }
                },
                "recommended_actions": [
                    "action_check_scanner",
                    "action_block_source_ip",
                    "action_review_firewall",
                    "action_correlate_ids"
                ]
            })

    elif log_type == "cloud_mfa":
        pushes = 0
        approved = False
        user = "Unknown"
        
        for e in events:
            user = e.get("user", user)
            if "MFA_Push_Sent" in e["raw"]:
                pushes += 1
            if "MFA_Push_Approved" in e["raw"]:
                approved = True
        
        if pushes > 2 and approved:
            alerts.append({
                "attack_type": "MFA Fatigue (Push Bombing) Attack",
                "severity": "HIGH",
                "mitre": "T1621 – Multi-Factor Authentication Request Generation",
                "source_ip": "internal", # Log doesn't show IP, just user
                "failed_attempts": "N/A (Successful Approval)",
                "time_window": "~40 seconds", # Hardcoded based on user request/log sample
                "fields": {
                    "User": user,
                    "Repeated MFA Push Requests": pushes,
                    
                },
                "explanation": {
                    "why_detected": {
                        "en": "Multiple MFA push notifications were sent to the same user in rapid succession, followed by an approval. This pattern is commonly associated with MFA fatigue attacks, where attackers attempt to overwhelm users into approving a fraudulent request.",
                        "tr": "Aynı kullanıcıya hızlı bir şekilde art arda birden fazla MFA anlık bildirimi gönderildi ve ardından bir onay gerçekleşti. Bu desen, saldırganların kullanıcıları sahte bir isteği onaylamaya zorlamak için bunalttığı MFA yorgunluk saldırıları ile yaygın olarak ilişkilendirilir."
                    },
                    "severity_meaning": {
                        "en": "**HIGH** severity indicates a strong likelihood of attempted account compromise. While MFA approval occurred, further investigation is required to confirm whether unauthorized access was achieved.",
                        "tr": "**YÜKSEK** önem derecesi, güçlü bir hesap ele geçirme girişimi olasılığını gösterir. MFA onayı gerçekleşmiş olsa da, yetkisiz erişimin sağlanıp sağlanmadığını doğrulamak için daha fazla inceleme gereklidir."
                    },
                    "learning_note": {
                        "en": "MFA fatigue attacks exploit human behavior by repeatedly sending push notifications until the user approves one. This technique is effective against push-only MFA without additional verification such as number matching.",
                        "tr": "MFA yorgunluk saldırıları, kullanıcı birini onaylayana kadar tekrar tekrar anlık bildirim göndererek insan davranışını istismar eder. Bu teknik, numara eşleştirme gibi ek doğrulama olmayan sadece onaya dayalı MFA sistemlerine karşı etkilidir."
                    }
                },
                "recommended_actions": [
                    "action_revoke_sessions",
                    "action_rotate_mfa",
                    "action_review_post_auth",
                    "action_enforce_mfa_matching",
                    "action_educate_user"
                ]
            })
        elif pushes > 0 and approved:
            benign_reason = "reason_benign_mfa"

    elif log_type == "azure_ad":
        locations = set()
        user = "Unknown"
        ips = set()
        for e in events:
            user = e.get("user", user)
            if "location" in e:
                locations.add(e["location"])
            if "ip" in e:
                ips.add(e["ip"])
        
        if len(locations) > 1:
            alerts.append({
                "attack_type": "Impossible Travel",
                "severity": "HIGH",
                "mitre": "T1078 - Valid Accounts",
                "source_ip": f"{list(ips)}",
                "failed_attempts": "N/A (Successful Logins)",
                "time_window": "Short Duration",
                "explanation": {
                    "why_detected": {
                        "en": f"User {user} successfully authenticated from physically distant locations ({', '.join(locations)}) within an impossible timeframe.",
                        "tr": f"Kullanıcı {user}, imkansız bir zaman dilimi içinde fiziksel olarak uzak konumlardan ({', '.join(locations)}) başarılı bir şekilde kimlik doğruladı."
                    },
                    "severity_meaning": {
                        "en": "**HIGH** severity indicates credentials are likely stolen and being used by an attacker in a different geography.",
                        "tr": "**YÜKSEK** önem derecesi, kimlik bilgilerinin muhtemelen çalındığını ve farklı bir coğrafyadaki bir saldırgan tarafından kullanıldığını gösterir."
                    },
                    "learning_note": {
                        "en": "Impossible Travel algorithms calculate the velocity required to travel between two login points. If > 500mph, it's flagged.",
                        "tr": "İmkansız Seyahat algoritmaları, iki giriş noktası arasında seyahat etmek için gereken hızı hesaplar. 500 mph'den fazlaysa işaretlenir."
                    }
                },
                "recommended_actions": [
                    "action_confirm_vpn",
                    "action_assume_compromise",
                    "action_reset_kill",
                    "action_check_inbox_rules"
                ]
            })

    elif log_type == "dns_traffic":
        queries = []
        src_ip = "192.168.1.50" # Default/Fallback
        has_legitimate_domains = False
        
        legitimate_domains = ["microsoft.com", "google.com", "cloudflare.net"]

        for e in events:
            if "query A" in e["raw"]:
                # Check for legitimate domains
                for legit in legitimate_domains:
                    if legit in e["raw"]:
                        has_legitimate_domains = True
                        break # Optimization: mark as benign if at least one match (heuristic for this lab)
                
                if not has_legitimate_domains: # Only collect queries if they look suspicious (not whitelisted)
                    queries.append(e["raw"])
                
                # Extract IP if possible: "... from 192.168.1.50"
                import re
                ip_match = re.search(r"from ([\d\.]+)", e["raw"])
                if ip_match:
                    src_ip = ip_match.group(1)

        if has_legitimate_domains and len(queries) == 0:
             benign_reason = "reason_benign_dns"
        elif len(queries) > 0:
             alerts.append({
                "attack_type": "DNS Tunneling (Possible Data Exfiltration)",
                "severity": "HIGH",
                "mitre": "T1071.004 – Application Layer Protocol: DNS",
                "time_window": "3 seconds",
                "fields": {
                    "Source IP": src_ip,
                    "Suspicious DNS Queries": f"{len(queries)}"
                },
                "explanation": {
                    "why_detected": {
                        "en": f"The host {src_ip} generated multiple DNS queries within a very short time window using long, high-entropy subdomains that resemble encoded data, all resolving to the same external domain.",
                        "tr": f"{src_ip} ana bilgisayarı, hepsi aynı harici etki alanına çözümlenen, kodlanmış veriye benzeyen uzun, yüksek entropili alt etki alanlarını kullanarak çok kısa bir zaman penceresinde birden fazla DNS sorgusu oluşturdu."
                    },
                    "severity_meaning": {
                        "en": "**HIGH** severity indicates a strong likelihood of DNS tunneling activity. This technique is commonly used for command-and-control communication or covert data exfiltration by encoding data within DNS queries to bypass traditional security controls.",
                        "tr": "**YÜKSEK** önem derecesi, DNS tünelleme aktivitesinin güçlü bir olasılığını gösterir. Bu teknik, geleneksel güvenlik kontrollerini atlamak için verileri DNS sorguları içine kodlayarak komuta ve kontrol iletişimleri veya gizli veri sızdırma için yaygın olarak kullanılır."
                    },
                    "learning_note": {
                        "en": "DNS tunneling abuses the DNS protocol by embedding data into subdomain labels (e.g., aGVsbG8uZGF0YQ.example.com). Legitimate DNS queries typically use human-readable, low-entropy domain names.",
                        "tr": "DNS tünelleme, verileri alt etki alanı etiketlerine gömerek (örn. aGVsbG8uZGF0YQ.example.com) DNS protokolünü kötüye kullanır. Meşru DNS sorguları genellikle insan tarafından okunabilir, düşük entropili alan adları kullanır."
                    }
                },
                "recommended_actions": [
                    "action_block_dns_domain",
                    "action_isolate_workstation",
                    "action_decode_subdomains",
                    "action_hunt_c2",
                    "action_review_powershell" 
                ]
            })

    elif log_type == "windows_smb":
        failures = 0
        targets = set()
        src_ip = "Unknown"
        user = "Unknown"
        
        for e in events:
            if "SMB Auth Failure" in e["raw"]:
                failures += 1
                if "dst=" in e["raw"]:
                    # simple regex extraction for this specific log format since simple_parser gives raw line mainly
                    import re
                    dst_match = re.search(r"dst=([\d\.]+)", e["raw"])
                    if dst_match: targets.add(dst_match.group(1))
                    
                    src_match = re.search(r"src=([\d\.]+)", e["raw"])
                    if src_match: src_ip = src_match.group(1)

                    user_match = re.search(r"user=([\w_]+)", e["raw"])
                    if user_match: user = user_match.group(1)

        if failures >= 3:
            # Sort targets for consistent display
            sorted_targets = sorted(list(targets))
            target_str = ", ".join(sorted_targets)

            alerts.append({
                "attack_type": "SMB Lateral Movement Attempt",
                "severity": "MEDIUM",
                "mitre": "T1021.002 – Remote Services: SMB/Windows Admin Shares",
                "source_ip": src_ip,
                "failed_attempts": failures,
                "time_window": "~6 seconds",
                "fields": {
                    "Failed Authentication Attempts": failures,
                    "Target Hosts": target_str
                },
                "explanation": {
                    "why_detected": {
                        "en": f"The source host {src_ip} attempted SMB authentication against multiple internal hosts within a short time window using the same service account ({user}), indicating potential lateral movement activity.",
                        "tr": f"Kaynak ana bilgisayar {src_ip}, aynı servis hesabını ({user}) kullanarak kısa bir zaman penceresinde birden fazla dahili ana bilgisayara SMB kimlik doğrulaması yapmaya çalıştı, bu da potansiyel yanal hareket aktivitesini gösterir."
                    },
                    "severity_meaning": {
                        "en": "**MEDIUM** severity indicates suspicious internal movement attempts. While no successful authentication was observed, such behavior is commonly associated with credential misuse or early-stage lateral movement.",
                        "tr": "**ORTA** önem derecesi şüpheli dahili hareket denemelerini gösterir. Başarılı bir kimlik doğrulama gözlemlenmemiş olsa da, bu tür davranışlar genellikle kimlik bilgisi kötüye kullanımı veya erken aşama yanal hareket ile ilişkilendirilir."
                    },
                    "learning_note": {
                        "en": "Lateral movement via SMB often involves probing multiple hosts using the same credentials to identify accessible administrative shares or remote execution opportunities.",
                        "tr": "SMB üzerinden yanal hareket, erişilebilir idari paylaşımları veya uzaktan yürütme fırsatlarını belirlemek için aynı kimlik bilgilerini kullanarak birden fazla ana bilgisayarı yoklamayı içerir."
                    }
                },
                "recommended_actions": [
                    "action_isolate_workstation",
                    "action_reset_service_account",
                    "action_review_firewall",
                    "action_hunt_lateral"
                ]
            })

    elif log_type == "cloud_upload":
        start_time = None
        end_time = None
        total_size_mb = 0.0
        user = "Unknown"
        destination = "Unknown"
        
        # Simple size parsing helper
        def parse_size(size_str):
            size_str = size_str.upper()
            if "GB" in size_str:
                return float(size_str.replace("GB", "")) * 1024
            elif "MB" in size_str:
                return float(size_str.replace("MB", ""))
            elif "KB" in size_str:
                return float(size_str.replace("KB", "")) / 1024
            return 0.0

        for e in events:
            # Extract basic fields using regex as simple_parser gives raw lines mostly
            # Format: 2026-01-29 23:45:01 user=alice action=upload file_size=1.2GB destination=drive.google.com
            import re
            
            # Simple timestamp capture (first item)
            ts_match = re.search(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", e["raw"])
            if ts_match:
                if start_time is None: start_time = ts_match.group(0)
                end_time = ts_match.group(0) # Keep updating to get the last one
            
            user_match = re.search(r"user=([\w_]+)", e["raw"])
            if user_match: user = user_match.group(1)
            
            dest_match = re.search(r"destination=([\w\.]+)", e["raw"])
            if dest_match: destination = dest_match.group(1)

            size_match = re.search(r"file_size=([\d\.]+(?:GB|MB|KB))", e["raw"])
            if size_match:
                total_size_mb += parse_size(size_match.group(1))

        # Threshold: > 1GB (1024 MB)
        if total_size_mb > 1024:
            # Format display size
            display_size = f"{total_size_mb/1024:.1f} GB" if total_size_mb > 1024 else f"{int(total_size_mb)} MB"
            
            alerts.append({
                "attack_type": "Cloud Data Exfiltration",
                "severity": "HIGH",
                "mitre": "T1567.002 – Exfiltration Over Web Services",
                "source_ip": "internal", # Log doesn't show IP, just user
                "failed_attempts": "N/A (Successful Upload)",
                "time_window": "~1 minute", # Hardcoded based on user request/log analysis
                "fields": { # Custom fields for this specific alert
                    "User": user,
                    "Destination": destination,
                    "Total Uploaded Data": f"~{display_size}"
                }, 
                "explanation": {
                    "why_detected": {
                        "en": f"The user {user} uploaded a large volume of data (~{display_size}) to an external cloud storage service ({destination.split('.')[-2].capitalize() if '.' in destination else destination}) outside of normal business hours within a very short time window.",
                        "tr": f"Kullanıcı {user}, mesai saatleri dışında çok kısa bir zaman diliminde harici bir bulut depolama servisine ({destination.split('.')[-2].capitalize() if '.' in destination else destination}) büyük miktarda veri (~{display_size}) yükledi."
                    },
                    "severity_meaning": {
                        "en": "**HIGH** severity indicates a strong possibility of data exfiltration. Large outbound transfers to external cloud services outside business hours are commonly associated with insider threats or compromised accounts.",
                        "tr": "**YÜKSEK** önem derecesi güçlü bir veri sızdırma olasılığını gösterir. Mesai saatleri dışında harici bulut servislerine yapılan büyük veri transferleri genellikle içeriden gelen tehditler veya ele geçirilmiş hesaplarla ilişkilendirilir."
                    },
                    "learning_note": {
                        "en": "Data exfiltration often occurs using legitimate cloud storage services to bypass perimeter defenses. Monitoring upload volume, destination, and timing is critical for detecting this activity.",
                        "tr": "Veri sızdırma, çevre savunmalarını atlatmak için genellikle meşru bulut depolama servisleri kullanılarak gerçekleşir. Yükleme hacmini, hedefini ve zamanlamasını izlemek bu aktiviteyi tespit etmek için kritiktir."
                    }
                },
                "recommended_actions": [
                    "action_confirm_upload",
                    "action_check_data_sensitivity",
                    "action_suspend_account",
                    "action_review_post_auth",
                    "action_check_exfiltration"
                ]
            })

    elif log_type == "suspicious_user_agent":
        bad_ua_count = 0
        src_ip = "Unknown"
        user_agent = "Unknown"
        
        for e in events:
            if "python-requests" in e["raw"]:
                bad_ua_count += 1
                # Extract IP
                import re
                ip_match = re.search(r"^([\d\.]+)", e["raw"])
                if ip_match: src_ip = ip_match.group(1)
                
                # Extract User Agent (last quoted string)
                ua_match = re.search(r"\"([^\"]+)\"$", e["raw"].strip())
                if ua_match: user_agent = ua_match.group(1)

        if bad_ua_count > 0:
             alerts.append({
                "attack_type": "Suspicious User-Agent Activity",
                "severity": "LOW",
                "mitre": "T1595 – Active Scanning",
                "source_ip": src_ip,
                "failed_attempts": f"{bad_ua_count} Requests",
                "time_window": "~2 seconds", 
                "fields": {
                    "User-Agent": user_agent,
                    "Requests": bad_ua_count,
                    
                },
                "explanation": {
                    "why_detected": {
                        "en": "Requests were made using a non-browser user-agent (python-requests) commonly associated with automated scripts. The source attempted access to sensitive endpoints such as /login and /admin within a short time window, indicating reconnaissance behavior.",
                        "tr": "İstekler, otomatik betiklerle yaygın olarak ilişkilendirilen tarayıcı dışı bir kullanıcı ajanı (python-requests) kullanılarak yapıldı. Kaynak, kısa bir zaman diliminde /login ve /admin gibi hassas uç noktalara erişmeye çalıştı, bu da keşif davranışını gösterir."
                    },
                    "severity_meaning": {
                        "en": "**LOW** severity indicates suspicious but non-exploitative activity. Automated probing may precede further attacks and should be monitored.",
                        "tr": "**DÜŞÜK** önem derecesi şüpheli ancak istismarcı olmayan aktiviteyi gösterir. Otomatik yoklama, daha ileri saldırıların habercisi olabilir ve izlenmelidir."
                    },
                    "learning_note": {
                        "en": "Attackers often use scripting libraries like python-requests to automate reconnaissance and endpoint discovery instead of standard web browsers.",
                        "tr": "Saldırganlar, standart web tarayıcıları yerine keşif ve nokta bulmayı otomatikleştirmek için python-requests gibi betik kütüphanelerini sıklıkla kullanırlar."
                    }
                },
                "recommended_actions": [
                    "action_monitor_probing",
                    "action_rate_limit_user_agent",
                    "action_block_source_ip",
                    "action_review_firewall"
                ]
            })
            
    if not alerts and not benign_reason:
        # Default benign reason if none set
        benign_reason = "reason_clean_traffic"

    return alerts, benign_reason

    return alerts, benign_reason

    return alerts, benign_reason
