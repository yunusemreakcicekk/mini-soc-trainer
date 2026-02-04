# 🛡️ Mini SOC Trainer

Mini SOC Trainer is an interactive, scenario-based cyber security training platform designed to simulate real-world Security Operations Center (SOC) workflows.

It helps users practice detection, triage, and decision-making skills using realistic attack scenarios and analyst feedback.

---

## 🎯 Who Is This For?

This project is suitable for:
- SOC Analyst candidates
- Blue Team students
- Cyber security learners who want hands-on practice
- Anyone interested in understanding how SOC decisions are made in real environments

No prior SOC experience is required.

---

## 🚀 Key Features

- ✅ Realistic SOC attack scenarios (SSH brute force, MFA fatigue, DNS tunneling, C2 beaconing, etc.)
- ✅ Analyst decision flow: True Positive / False Positive
- ✅ Confidence & severity scoring
- ✅ MITRE ATT&CK–aligned thinking (conceptual mapping)
- ✅ Analyst performance dashboard
- ✅ Scenario-based learning instead of theory
- ✅ Web-based interface (Flask)

---

## 🧠 How It Works

1. The system presents a realistic security scenario
2. You analyze the context, logs, and indicators
3. You decide whether the alert is a True Positive or False Positive
4. The system provides detailed analyst feedback
5. Your performance is tracked on the dashboard

This mirrors how analysts work in real SOC environments.

---

## 🖥️ Run Locally (Quick Start)

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yunusemreakcicekk/mini-soc-trainer.git
cd mini-soc-trainer

2️⃣ Install dependencies
pip install -r requirements.txt

3️⃣ Start the web application
python web/app.py

4️⃣ Open in browser
http://localhost:10000

📂 Project Structure (Simplified)
mini-soc-trainer/
├── detection/        # Detection logic (brute force, recon, etc.)
├── parsers/          # Log parsing modules
├── training_lab/     # Scenarios, answers, feedback engine
├── education/        # Explanations and severity guides
├── web/              # Flask web app (UI + routes)
│   ├── templates/
│   ├── static/
│   └── app.py
├── requirements.txt
└── README.md

🧪 Training Scenarios Include

SSH brute force

Password spraying

Credential compromise

MFA fatigue attacks

DNS tunneling

Command & Control beaconing

Insider data exfiltration

Lateral movement

Web & API reconnaissance

False positive analysis cases

📊 Analyst Performance Dashboard

Accuracy tracking

Scenario history

Difficulty-based performance

True Positive / False Positive ratios

🔐 Disclaimer

This project is for educational purposes only.
All logs and scenarios are simulated and do not represent real environments.

📌 Roadmap (Planned)

🔹 Live public demo

🔹 Full MITRE ATT&CK technique mapping

🔹 Desktop application build

🔹 More advanced SOC scenarios

🤝 Contributing

Contributions, ideas, and feedback are welcome.
Feel free to open issues or submit pull requests.

👤 Author

Yunus Emre Akçiçek
Cyber Security & SOC Enthusiast