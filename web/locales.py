# Localization Dictionary
# Keys should be unique identifiers for UI elements

UI_STRINGS = {
    # Navbar & Branding
    "nav_title": {
        "en": "Mini SOC Trainer",
        "tr": "Mini SOC Eğitmeni"
    },
    "nav_home": {
        "en": "Home",
        "tr": "Ana Sayfa"
    },
    "nav_level": {
        "en": "Level",
        "tr": "Seviye"
    },
    
    # Home Page (Index)
    "hero_subtitle": {
        "en": "Master the Art of Security Operations Center Analysis",
        "tr": "Güvenlik Operasyon Merkezi Analiz Sanatında Ustalaşın"
    },
    "card_training_title": {
        "en": "Training Lab",
        "tr": "Eğitim Laboratuvarı"
    },
    "card_training_desc": {
        "en": "Practice SOC decision-making. Analyze scenarios, classify alerts as True/False Positives, and get instant feedback.",
        "tr": "SOC karar verme pratiği yapın. Senaryoları analiz edin, alarmları Doğru/Yanlış Pozitif olarak sınıflandırın ve anında geri bildirim alın."
    },
    "card_analyzer_title": {
        "en": "Log Analyzer",
        "tr": "Log Analizörü"
    },
    "card_analyzer_desc": {
        "en": "Manually inspect raw logs (Linux, Windows, Network) and run automated detection rules to generate detailed reports.",
        "tr": "Ham logları (Linux, Windows, Ağ) manuel olarak inceleyin ve detaylı raporlar oluşturmak için otomatik tespit kurallarını çalıştırın."
    },
    "card_dashboard_title": {
        "en": "My Dashboard",
        "tr": "Panelim"
    },
    "card_dashboard_desc": {
        "en": "Track your progress. Review your accuracy scores, recent activity history, and difficulty level performance.",
        "tr": "İlerlemenizi takip edin. Doğruluk puanlarınızı, son aktivite geçmişinizi ve zorluk seviyesi performansınızı inceleyin."
    },
    "btn_how_it_works": {
        "en": "How This Platform Works",
        "tr": "Bu Platform Nasıl Çalışır"
    },

    # Dashboard
    "dash_title": {
        "en": "Analyst Performance Dashboard",
        "tr": "Analist Performans Paneli"
    },
    "dash_stats_title": {
        "en": "Analyst Stats",
        "tr": "Analist İstatistikleri"
    },
    "dash_accuracy": {
        "en": "Accuracy",
        "tr": "Doğruluk"
    },
    "dash_total_scenarios": {
        "en": "Total Scenarios",
        "tr": "Toplam Senaryo"
    },
    "dash_correct_incorrect": {
        "en": "Correct / Incorrect",
        "tr": "Doğru / Yanlış"
    },
    "dash_streak": {
        "en": "Current Streak",
        "tr": "Mevcut Seri"
    },
    "dash_recent_activity": {
        "en": "Recent Activity (Last 10)",
        "tr": "Son Aktiviteler (Son 10)"
    },
    "dash_col_scenario": {
        "en": "Scenario",
        "tr": "Senaryo"
    },
    "dash_col_difficulty": {
        "en": "Difficulty",
        "tr": "Zorluk"
    },
    "dash_col_result": {
        "en": "Result",
        "tr": "Sonuç"
    },
    "dash_no_activity": {
        "en": "No scenarios attempted yet.",
        "tr": "Henüz denenmiş senaryo yok."
    },
    "dash_back_training": {
        "en": "Back to Training",
        "tr": "Eğitime Dön"
    },
    "badge_correct": {
        "en": "Correct",
        "tr": "Doğru"
    },
    "badge_incorrect": {
        "en": "Incorrect",
        "tr": "Yanlış"
    },
    
    # Training Lab
    "train_score": {
        "en": "Score",
        "tr": "Puan"
    },
    "train_reset_score": {
        "en": "Reset Score",
        "tr": "Skoru Sıfırla"
    },
    "train_dashboard_btn": {
        "en": "Performance Dashboard",
        "tr": "Performans Paneli"
    },
    "train_context_baseline": {
        "en": "CONTEXT/BASELINE",
        "tr": "BAĞLAM/TEMEL ÇİZGİ"
    },
    "train_severity": {
        "en": "Severity",
        "tr": "Önem Derecesi"
    },
    "train_confidence": {
        "en": "Confidence",
        "tr": "Güven"
    },
    "train_btn_true_positive": {
        "en": "True Positive",
        "tr": "Gerçek Pozitif"
    },
    "train_btn_false_positive": {
        "en": "False Positive",
        "tr": "Yanlış Pozitif"
    },
    "train_correct_ir": {
        "en": "Correct! Incident Response Required",
        "tr": "Doğru! Olay Müdahalesi Gerekli"
    },
    "train_correct": {
        "en": "Correct",
        "tr": "Doğru"
    },
    "train_incorrect": {
        "en": "Incorrect",
        "tr": "Yanlış"
    },
    "train_ir_feedback": {
        "en": "IR Feedback",
        "tr": "IR Geri Bildirimi"
    },
    "train_btn_next": {
        "en": "Next Scenario",
        "tr": "Sonraki Senaryo"
    },

    # Log Analyzer
    "analyze_title": {
        "en": "Log Analyzer (Predefined Training Logs)",
        "tr": "Log Analizörü (Önceden Tanımlanmış Eğitim Logları)"
    },
    "analyze_step_1": {
        "en": "1. Select a Log File",
        "tr": "1. Bir Log Dosyası Seçin"
    },
    "analyze_step_2": {
        "en": "2. Analyze Log",
        "tr": "2. Logu Analiz Et"
    },
    "analyze_btn_analyze": {
        "en": "Analyze Selected Log",
        "tr": "Seçili Logu Analiz Et"
    },
    "analyze_step_3": {
        "en": "3. Detection Results",
        "tr": "3. Tespit Sonuçları"
    },
    "analyze_no_log_selected": {
        "en": "Please select a log file first.",
        "tr": "Lütfen önce bir log dosyası seçin."
    },
    "analyze_analyzing": {
        "en": "Analyzing...",
        "tr": "Analiz ediliyor..."
    },
    "analyze_clean": {
        "en": "No threats detected. This log appears clean.",
        "tr": "Tehdit tespit edilmedi. Bu log temiz görünüyor."
    },
     "analyze_benign": {
        "en": "✅ Benign Activity Detected",
        "tr": "✅ Zararsız Aktivite Tespit Edildi"
    },
     "analyze_why_benign": {
        "en": "Why is this Benign?",
        "tr": "Neden Zararsız?"
    },
    "analyze_why_detected": {
        "en": "Why was this detected?",
        "tr": "Neden tespit edildi?"
    },
    "analyze_severity_meaning": {
        "en": "Severity Meaning:",
        "tr": "Önem Derecesi Anlamı:"
    },
    "analyze_learning_note": {
        "en": "Learning Note:",
        "tr": "Öğrenme Notu:"
    },
    "analyze_rec_actions": {
        "en": "Recommended SOC Actions:",
        "tr": "Önerilen SOC İşlemleri:"
    },
    
    # Info Panel (Index)
    "info_title": {
        "en": "Welcome to the SOC Simulation",
        "tr": "SOC Simülasyonuna Hoş Geldiniz"
    },
    "info_step1_title": {
        "en": "1. Choose a Mode",
        "tr": "1. Bir Mod Seçin"
    },
    "info_step1_desc": {
        "en": "Start with <strong>Training Lab</strong> for guided scenarios or <strong>Log Analyzer</strong> for raw log inspection.",
        "tr": "Rehberli senaryolar için <strong>Eğitim Laboratuvarı</strong> veya ham log incelemesi için <strong>Log Analizörü</strong> ile başlayın."
    },
    "info_step2_title": {
        "en": "2. Analyze & Decide",
        "tr": "2. Analiz Et ve Karar Ver"
    },
    "info_step2_desc": {
        "en": "Review the evidence. Is it a real threat (True Positive) or a false alarm (False Positive)?",
        "tr": "Delilleri inceleyin. Gerçek bir tehdit mi (Gerçek Pozitif) yoksa yanlış alarm mı (Yanlış Pozitif)?"
    },
    "info_step3_title": {
        "en": "3. Learn & Improve",
        "tr": "3. Öğren ve Geliştir"
    },
    "info_step3_desc": {
        "en": "Read the detailed feedback. Understand the 'Why' and master the MITRE ATT&CK patterns.",
        "tr": "Detaylı geri bildirimleri okuyun. 'Neden'ini anlayın ve MITRE ATT&CK kalıplarında ustalaşın."
    },

    # Common Labels
    "lbl_baseline": {
        "en": "Baseline",
        "tr": "Referans (Baseline)"
    },
    "lbl_observed": {
        "en": "Observed Activity",
        "tr": "Gözlemlenen Aktivite"
    },
    "lbl_attack_type": {
        "en": "Attack Type",
        "tr": "Saldırı Türü"
    },
    "lbl_summary": {
        "en": "Summary",
        "tr": "Özet"
    },
    "lbl_source_ip": {
        "en": "Source IP",
        "tr": "Kaynak IP"
    },
    "lbl_time_window": {
        "en": "Time Window",
        "tr": "Zaman Penceresi"
    },
    "lbl_failed_auth_attempts": {
        "en": "Failed Authentication Attempts",
        "tr": "Başarısız Kimlik Doğrulama Denemeleri"
    },
    "lbl_failed_login_attempts": {
        "en": "Failed Login Attempts",
        "tr": "Başarısız Giriş Denemeleri"
    },
    "lbl_target_hosts": {
        "en": "Target Hosts",
        "tr": "Hedef Ana Bilgisayarlar"
    },
    "lbl_target_service": {
        "en": "Target Service",
        "tr": "Hedef Servis"
    },
    "lbl_enumerated_paths": {
        "en": "Enumerated Paths",
        "tr": "Taranan Yollar"
    },
    "lbl_user_agent": {
        "en": "User-Agent",
        "tr": "Kullanıcı Ajanı"
    },
    "lbl_requests": {
        "en": "Requests",
        "tr": "İstekler"
    },
    # Common Labels
    "lbl_difficulty": {
        "en": "Difficulty",
        "tr": "Zorluk"
    },
    "lbl_easy": {
        "en": "Easy",
        "tr": "Kolay"
    },
    "lbl_medium": {
        "en": "Medium",
        "tr": "Orta"
    },
    "lbl_hard": {
        "en": "Hard",
        "tr": "Zor"
    },
    
    # Log Analyzer
    "lbl_predefined_logs": {
        "en": "Predefined Training Logs",
        "tr": "Ön Tanımlı Eğitim Kayıtları"
    },
    "analyze_results_title": {
        "en": "Detection Results",
        "tr": "Tespit Sonuçları"
    },
    "analyze_loading": {
        "en": "Analyzing log patterns...",
        "tr": "Log desenleri analiz ediliyor..."
    },
    "analyze_select_log": {
        "en": "Select a Log File",
        "tr": "Bir Log Dosyası Seçin"
    },
    "analyze_view_log": {
        "en": "Raw Log Viewer",
        "tr": "Ham Log Görüntüleyici"
    },
    "analyze_instruction": {
        "en": "Review the log before analyzing.",
        "tr": "Analiz etmeden önce logu inceleyiniz."
    },
    "analyze_no_logs": {
        "en": "No logs found in training_logs/.",
        "tr": "training_logs/ dizininde log bulunamadı."
    },
    
    # Benign / Clean Reasons
    "reason_clean_traffic": {
        "en": "No threats detected. This log appears clean.",
        "tr": "Tehdit tespit edilmedi. Bu log temiz görünüyor."
    },
    "reason_benign_dns": {
        "en": "High volume DNS queries observed, but domains belong to known legitimate services with low entropy.",
        "tr": "Yüksek hacimli DNS sorguları görüldü, ancak alan adları düşük entropiye sahip bilinen meşru servislere ait."
    },
    "reason_benign_mfa": {
        "en": "Single MFA push request followed by immediate approval is consistent with a legitimate user login.",
        "tr": "Tek bir MFA onay isteğinin ardından gelen anlık onay, meşru bir kullanıcı girişi ile tutarlıdır."
    },
    "reason_benign_general": {
        "en": "Activity appears consistent with baseline behavior.",
        "tr": "Aktivite, temel davranış çizgisiyle tutarlı görünüyor."
    },
    
    # Scenario Details keys (existing ones but double checking if used)
    
    # Titles & Headings
    "title_training_lab": {
        "en": "Training Lab",
        "tr": "Eğitim Laboratuvarı"
    },
    "title_log_analyzer": {
        "en": "Log Analyzer",
        "tr": "Log Analizörü"
    },
    "title_dashboard": {
        "en": "Analyst Performance Dashboard",
        "tr": "Analist Performans Paneli"
    },

    # Buttons
    "btn_analyze_log": {
        "en": "⚡ Analyze This Log",
        "tr": "⚡ Bu Logu Analiz Et"
    },
    "btn_refresh_list": {
        "en": "🔄 Refresh Log List",
        "tr": "🔄 Log Listesini Yenile"
    },

    "lbl_easy": {
        "en": "Easy",
        "tr": "Kolay"
    },
    "lbl_medium": {
        "en": "Medium",
        "tr": "Orta"
    },
    "lbl_hard": {
        "en": "Hard",
        "tr": "Zor"
    },
    "lbl_feedback_title_incorrect": {
        "en": "Incorrect",
        "tr": "Yanlış"
    },
    "lbl_feedback_title_correct": {
        "en": "Correct!",
        "tr": "Doğru!"
    },
    "lbl_explanation": {
        "en": "Explanation",
        "tr": "Açıklama"
    },
    "lbl_feedback": {
        "en": "Feedback",
        "tr": "Geri Bildirim"
    },
    "btn_next_scenario": {
        "en": "Next Scenario",
        "tr": "Sonraki Senaryo"
    },
    
    # Severity & Status Labels
    "lbl_critical": {
        "en": "CRITICAL",
        "tr": "KRİTİK"
    },
    "lbl_high": {
        "en": "HIGH",
        "tr": "YÜKSEK"
    },
    "lbl_medium": {
        "en": "MEDIUM",
        "tr": "ORTA"
    },
    "lbl_low": {
        "en": "LOW",
        "tr": "DÜŞÜK"
    },
    "lbl_safe": {
        "en": "SAFE",
        "tr": "GÜVENLİ"
    },
    "lbl_info": {
        "en": "INFO",
        "tr": "BİLGİ"
    },
    "lbl_clean": {
        "en": "CLEAN",
        "tr": "TEMİZ"
    },

    # Recommended Action Keys
    "action_confirm_vpn": {
        "en": "Confirm with the user if they are using a VPN.",
        "tr": "Kullanıcının VPN kullanıp kullanmadığını teyit edin."
    },
    "action_assume_compromise": {
        "en": "If not a VPN, assume account compromise.",
        "tr": "VPN değilse, hesabın ele geçirildiğini varsayın."
    },
    "action_reset_kill": {
        "en": "Reset password and kill active sessions.",
        "tr": "Parolayı sıfırlayın ve aktif oturumları sonlandırın."
    },
    "action_check_inbox_rules": {
        "en": "Check for creation of inbox rules or new device registrations.",
        "tr": "Gelen kutusu kuralları veya yeni cihaz kayıtlarını kontrol edin."
    },
    "action_revoke_sessions": {
        "en": "Immediately review and revoke active sessions for the user",
        "tr": "Kullanıcı için aktif oturumları derhal inceleyin ve iptal edin"
    },
    "action_rotate_mfa": {
        "en": "Reset the user’s password and rotate MFA credentials",
        "tr": "Kullanıcının parolasını ve MFA kimlik bilgilerini sıfırlayın"
    },
    "action_review_post_auth": {
        "en": "Review post-authentication activity for suspicious behavior",
        "tr": "Şüpheli davranışlar için kimlik doğrulama sonrası aktiviteleri inceleyin"
    },
    "action_enforce_mfa_matching": {
        "en": "Enforce MFA number matching or phishing-resistant MFA",
        "tr": "MFA numara eşleştirmeyi veya kimlik avına dirençli MFA'yı zorunlu kılın"
    },
    "action_educate_user": {
        "en": "Educate the user to report unsolicited MFA prompts",
        "tr": "İstenmeyen MFA istemlerini bildirmesi konusunda kullanıcıyı eğitin"
    },
    "action_isolate_workstation": {
        "en": "Isolate the affected workstation immediately",
        "tr": "Etkilenen iş istasyonunu derhal izole edin"
    },
    "action_capture_memory": {
        "en": "Capture memory and check for malicious processes",
        "tr": "Bellek imajı alın ve kötü amaçlı süreçleri kontrol edin"
    },
    "action_review_powershell": {
        "en": "Review PowerShell history/transcript logs",
        "tr": "PowerShell geçmişini veya transkript loglarını inceleyin"
    },
    "action_block_url": {
        "en": "Block the remote URL/IP at the firewall",
        "tr": "Uzak URL/IP'yi güvenlik duvarında engelleyin"
    },
    "action_check_scanner": {
        "en": "Check if the source IP is an authorized scanner",
        "tr": "Kaynak IP'nin yetkili bir tarayıcı olup olmadığını kontrol edin"
    },
    "action_block_source_ip": {
        "en": "Block the source IP at the perimeter firewall if unauthorized",
        "tr": "Yetkisiz ise kaynak IP'yi çevre güvenlik duvarında engelleyin"
    },
    "action_review_firewall": {
        "en": "Review firewall logs to see if any connections were accepted",
        "tr": "Herhangi bir bağlantının kabul edilip edilmediğini görmek için güvenlik duvarı loglarını inceleyin"
    },
    "action_correlate_ids": {
        "en": "Correlate with IDS/IPS logs for exploit signatures",
        "tr": "İstismar imzaları için IDS/IPS logları ile ilişkilendirin"
    },
    "action_block_dns_domain": {
        "en": "Block the suspicious root domain at the DNS resolver",
        "tr": "DNS çözümleyicide şüpheli kök etki alanını engelleyin"
    },
    "action_decode_subdomains": {
        "en": "Decode and analyze the queried subdomains",
        "tr": "Sorgulanan alt etki alanlarını çözün ve analiz edin"
    },
    "action_hunt_c2": {
        "en": "Hunt for additional command-and-control or beaconing activity",
        "tr": "Ek komuta-kontrol veya işaretleşme aktivitelerini araştırın"
    },
    "action_reset_service_account": {
        "en": "Reset or rotate credentials for the affected service account",
        "tr": "Etkilenen servis hesabı için kimlik bilgilerini sıfırlayın"
    },
    "action_hunt_lateral": {
        "en": "Hunt for lateral movement techniques (RDP, WMI, PsExec)",
        "tr": "Yanal hareket tekniklerini (RDP, WMI, PsExec) araştırın"
    },
    "action_confirm_upload": {
        "en": "Confirm whether the upload was business-related and authorized",
        "tr": "Yüklemenin iş odaklı ve yetkili olup olmadığını teyit edin"
    },
    "action_check_data_sensitivity": {
        "en": "Check the file types and sensitivity of uploaded data",
        "tr": "Dosya türlerini ve yüklenen verilerin hassasiyetini kontrol edin"
    },
    "action_suspend_account": {
        "en": "Temporarily suspend the account if unauthorized",
        "tr": "Yetkisiz ise hesabı geçici olarak askıya alın"
    },
    "action_check_exfiltration": {
        "en": "Check for additional exfiltration attempts or automation",
        "tr": "Ek veri sızdırma girişimlerini veya otomasyonu kontrol edin"
    },
    "action_rate_limit_user_agent": {
        "en": "Apply rate limiting or WAF rules for automated user-agents",
        "tr": "Otomatik kullanıcı ajanları için hız sınırlaması veya WAF kuralları uygulayın"
    },
    "action_monitor_probing": {
        "en": "Monitor the source IP for additional probing or exploits",
        "tr": "Ek araştırma veya istismarlar için kaynak IP'yi izleyin"
    },
    "action_ssh_key_auth": {
        "en": "Ensure SSH uses key-based authentication instead of passwords",
        "tr": "SSH'ın parola yerine anahtar tabanlı kimlik doğrulama kullandığından emin olun"
    },
    "action_review_ssh_exposure": {
        "en": "Review SSH exposure to the internet",
        "tr": "SSH'ın internete maruz kalma durumunu inceleyin"
    },
    "action_monitor_escalation": {
        "en": "Monitor for escalation or successful login attempts",
        "tr": "Yetki yükseltme veya başarılı giriş denemelerini izleyin"
    },
    "action_rate_limit_dir_enum": {
        "en": "Apply rate limiting or WAF rules against directory enumeration",
        "tr": "Dizin numaralandırmaya karşı hız sınırlaması veya WAF kuralları uygulayın"
    },
    "action_review_web_config": {
        "en": "Review web server configuration to protect sensitive directories",
        "tr": "Hassas dizinleri korumak için web sunucusu yapılandırmasını inceleyin"
    },
    "action_verify_cdn": {
        "en": "Verify if the source IP belongs to a known CDN",
        "tr": "Kaynak IP'nin bilinen bir CDN'e ait olup olmadığını doğrulayın"
    },
    "action_review_monitoring": {
        "en": "Review monitoring configuration for misconfigured probes",
        "tr": "Yanlış yapılandırılmış sondalar için izleme yapılandırmasını inceleyin"
    },
    "action_rate_limit_health": {
        "en": "If IP is unknown, apply rate limiting to /health endpoint",
        "tr": "IP bilinmiyorsa, /health uç noktasına hız sınırlaması uygulayın"
    },
    
    # Navigation & Progress
    "lbl_scenario_idx": {
        "en": "Scenario",
        "tr": "Senaryo"
    },
    "btn_prev_scenario": {
        "en": "Previous Scenario",
        "tr": "Önceki Senaryo"
    },
    "btn_next_scenario_nav": {
        "en": "Next Scenario",
        "tr": "Sonraki Senaryo"
    }
}

