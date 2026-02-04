from collections import defaultdict
from datetime import timedelta

# Thresholds (training amaçlı)
DIR_BRUTE_THRESHOLD = 3
HEALTH_CHECK_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)

def detect_web_recon(events):
    alerts = []

    # IP -> timestamps & paths
    ip_requests = defaultdict(list)

    for e in events:
        # store timestamp, path, status (if present)
        status = e.get("status")
        ip_requests[e["ip"]].append((e["timestamp"], e["path"], status))

    for ip, requests in ip_requests.items():
        # zamana göre sırala
        requests.sort(key=lambda x: x[0])

        # 1. Directory Enumeration (404s)
        for i in range(len(requests)):
            start_time = requests[i][0]
            
            window_404 = [
                path for (ts, path, status) in requests
                if start_time <= ts <= start_time + TIME_WINDOW and status in [403, 404]
            ]

            unique_paths = set(window_404)

            if len(unique_paths) >= DIR_BRUTE_THRESHOLD:
                alerts.append({
                    "attack_type": "Web Directory Enumeration",
                    "mitre": "T1595 – Active Scanning",
                    "severity": "MEDIUM",
                    "source_ip": ip,
                    "failed_attempts": len(unique_paths),
                    "time_window": "~6 seconds",
                    "fields": {
                        "lbl_enumerated_paths": len(unique_paths),
                        
                    },
                    "explanation": {
                        "why_detected": {
                            "en": "Multiple requests to common administrative and backup directories were observed from a single source IP within a short time window. The pattern of 403 and 404 responses is consistent with automated directory enumeration tools.",
                            "tr": "Tek bir kaynak IP'den kısa bir zaman diliminde yaygın idari ve yedekleme dizinlerine çok sayıda istek gözlemlendi. 403 ve 404 yanıt kalıbı, otomatik dizin numaralandırma araçlarıyla tutarlıdır."
                        },
                        "severity_meaning": {
                            "en": "**MEDIUM** severity indicates reconnaissance activity targeting web application structure. While no exploitation occurred, directory enumeration is commonly used to identify attack surfaces for follow-up attacks.",
                            "tr": "**ORTA** önem derecesi, web uygulama yapısını hedef alan keşif faaliyetini gösterir. İstismar gerçekleşmemiş olsa da, dizin numaralandırma genellikle takip eden saldırılar için saldırı yüzeylerini belirlemek amacıyla kullanılır."
                        },
                        "learning_note": {
                            "en": "Attackers often probe common directory names such as /admin, /backup, or /config to discover exposed management interfaces or sensitive files.",
                            "tr": "Saldırganlar, maruz kalan yönetim arayüzlerini veya hassas dosyaları keşfetmek için genellikle /admin, /backup veya /config gibi yaygın dizin adlarını yoklarlar."
                        }
                    },
                    "recommended_actions": [
                        "action_rate_limit_dir_enum",
                        "action_monitor_probing",
                        "action_review_web_config",
                        "action_correlate_ids"
                    ]
                })
                # Break inner loop to avoid duplicate alerts for the same window
                break

        # 2. Health Check Flood (200 OK on specific paths)
        for i in range(len(requests)):
            start_time = requests[i][0]
            
            health_keywords = ["health", "healthcheck"]
            
            window_health = [
                path for (ts, path, status) in requests
                if start_time <= ts <= start_time + TIME_WINDOW 
                and status == 200
                and any(k in path.lower() for k in health_keywords)
            ]
            
            # Count total requests, not just unique paths (flood)
            if len(window_health) >= HEALTH_CHECK_THRESHOLD:
                 # Check if we already added this alert type for this IP to avoidspam
                if not any(a["source_ip"] == ip and a["attack_type"] == "CDN Health Check Flood" for a in alerts):
                    alerts.append({
                        "attack_type": "CDN Health Check Flood",
                        "mitre": "T1498 – Network Denial of Service",
                        "severity": "LOW",
                        "source_ip": ip,
                        "failed_attempts": len(window_health),
                        "time_window": "14 seconds",
                        "fields": {
                            "lbl_requests": len(window_health)
                        },
                        "explanation": {
                             "why_detected": {
                                 "en": "High frequency /health endpoint requests from a single source IP within a very short time window exceeded the normal baseline for health check activity.",
                                 "tr": "Tek bir kaynak IP adresinden çok kısa bir zaman penceresinde yapılan yüksek frekanslı /health uç noktası istekleri, normal sağlık kontrolü aktivitesi temel çizgisini aştı."
                             },
                             "severity_meaning": {
                                 "en": "**LOW** severity indicates potentially misconfigured monitoring or aggressive health checks. While often benign, excessive frequency can impact service availability or mask denial-of-service attempts.",
                                 "tr": "**DÜŞÜK** önem derecesi, potansiyel olarak yanlış yapılandırılmış izleme veya agresif sağlık kontrollerini gösterir. Genellikle zararsız olsa da, aşırı frekans hizmet kullanılabilirliğini etkileyebilir veya hizmet reddi girişimlerini maskeleyebilir."
                             },
                             "learning_note": {
                                 "en": "Health check endpoints are typically polled at fixed intervals (e.g., every 30–60 seconds). Requests every 1–2 seconds significantly deviate from expected behavior.",
                                 "tr": "Sağlık kontrolü uç noktaları tipik olarak sabit aralıklarla (örn. her 30-60 saniyede bir) yoklanır. Her 1-2 saniyede bir gelen istekler, beklenen davranıştan önemli ölçüde sapar."
                             }
                        },
                        "recommended_actions": [
                            "action_verify_cdn",
                            "action_review_monitoring",
                            "action_rate_limit_health",
                            "action_monitor_escalation"
                        ]
                    })
                break

    
    # Benign Reason Check
    benign_reason = None
    if not alerts:
        # Check if we saw health checks that were below threshold (benign)
        has_health_checks = False
        for ip, requests in ip_requests.items():
             for _, path, status in requests:
                 if status == 200 and ("health" in path.lower() or "healthcheck" in path.lower()):
                     has_health_checks = True
                     break
        
        if has_health_checks:
            benign_reason = "Health check requests are within normal frequency and match expected CDN / monitoring behavior."

    return alerts, benign_reason
