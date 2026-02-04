import sys
import os
import json
import random
from collections import defaultdict
from flask import Flask, render_template, request, session, redirect, url_for, jsonify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from werkzeug.utils import secure_filename
from parsers.log_type_detector import detect_log_type
from parsers.linux_auth import parse_linux_auth_log
from detection.brute_force import detect_brute_force
from parsers.web_access import parse_web_access_log
from detection.web_recon import detect_web_recon

app = Flask(__name__)
app.secret_key = "mini-soc-trainer-secret"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads_web")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# === HELPERS ===

from locales import UI_STRINGS

def get_text(obj, lang="en"):
    """
    Helper to extract text from bilingual dictionary.
    If obj is a string key present in UI_STRINGS, return the translated text.
    If obj is a dict, return obj[lang].
    Otherwise return str(obj).
    """
    if isinstance(obj, dict):
        return obj.get(lang, obj.get("en", "Missing Text"))
    
    # Check if it's a key in our UI dict
    if isinstance(obj, str) and obj in UI_STRINGS:
        return UI_STRINGS[obj].get(lang, UI_STRINGS[obj].get("en", obj))
        
    return str(obj)

@app.context_processor
def utility_processor():
    return dict(get_text=get_text, ui=UI_STRINGS)

def init_session():
    if "score" not in session:
        session["score"] = {"correct": 0, "incorrect": 0, "total": 0}
    if "lang" not in session:
        session["lang"] = "en"
    if "difficulty" not in session:
        session["difficulty"] = "Medium"
    if "history" not in session:
        session["history"] = [] # List of {scenario_id, result, difficulty, timestamp}

def load_training_data():
    with open(os.path.join(BASE_DIR, "training_lab", "scenarios.json"), encoding="utf-8") as f:
        scenarios = json.load(f)
    with open(os.path.join(BASE_DIR, "training_lab", "answers.json"), encoding="utf-8") as f:
        answers = json.load(f)
    with open(os.path.join(BASE_DIR, "training_lab", "feedback.json"), encoding="utf-8") as f:
        feedback = json.load(f)
    return scenarios, answers, feedback

# === ROUTES ===

@app.route("/")
def index():
    init_session()
    return render_template("index.html")

@app.route("/set_language/<lang>")
def set_language(lang):
    if lang in ["en", "tr"]:
        session["lang"] = lang
        session.modified = True
    return redirect(request.referrer or url_for("index"))

@app.route("/set_difficulty/<diff>")
def set_difficulty(diff):
    if diff in ["Easy", "Medium", "Hard"]:
        session["difficulty"] = diff
        session.modified = True
    return redirect(request.referrer or url_for("training"))

@app.route("/reset_score")
def reset_score():
    if "score" in session:
        session["score"] = {"correct": 0, "incorrect": 0, "total": 0}
        session.modified = True
    return redirect(url_for("training"))

@app.route("/analyze", methods=["GET"])
def analyze():
    # Only render the UI, no logic here anymore
    return render_template("analyze.html")

@app.route("/logs")
def list_logs():
    """List available logs in training_logs directory."""
    log_dir = os.path.join(BASE_DIR, "training_logs")
    if not os.path.exists(log_dir):
        return jsonify([])
    
    files = [f for f in os.listdir(log_dir) if f.endswith(".log")]
    return jsonify(files)

@app.route("/view_log/<log_name>")
def view_log(log_name):
    """Return raw log content safely."""
    log_dir = os.path.join(BASE_DIR, "training_logs")
    safe_name = secure_filename(log_name)
    file_path = os.path.join(log_dir, safe_name)
    
    if not os.path.exists(file_path):
        return "File not found", 404
        
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return content
    except Exception as e:
        return str(e), 500

from parsers.simple_parser import parse_simple_log
from detection.simple_rules import detect_simple_threats

@app.route("/analyze_log/<log_name>")
def analyze_log_file(log_name):
    """Run detection on selected log file."""
    log_dir = os.path.join(BASE_DIR, "training_logs")
    safe_name = secure_filename(log_name)
    file_path = os.path.join(log_dir, safe_name)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    log_type = detect_log_type(file_path)
    alerts = []

    # Standard Parsers
    if log_type == "linux_auth":
        events = parse_linux_auth_log(file_path)
        alerts, benign_reason = detect_brute_force(events)
        return jsonify({"alerts": alerts, "log_type": log_type, "benign_reason": benign_reason})
    elif log_type == "web_access":
        events = parse_web_access_log(file_path)
        alerts, benign_reason = detect_web_recon(events)
        return jsonify({"alerts": alerts, "log_type": log_type, "benign_reason": benign_reason})
    # Simple Rule-Based Parsers
    elif log_type in ["windows_powershell", "network_traffic", "cloud_mfa", "azure_ad", "dns_traffic", "windows_smb", "cloud_upload", "suspicious_user_agent"]:
        events = parse_simple_log(file_path)
        alerts, benign_reason = detect_simple_threats(events, log_type)
        return jsonify({"alerts": alerts, "log_type": log_type, "benign_reason": benign_reason})
    else:
        # Fallback for "unknown" to avoid "Unsupported log type" error blocking UI
        # We try to apply ALL simple rules just in case
        events = parse_simple_log(file_path)
        alerts, benign_reason = detect_simple_threats(events, "network_traffic") # Try generic port scan check
        if not alerts and not benign_reason:
             return jsonify({"error": f"Unsupported log type: {log_type}", "alerts": []})

    return jsonify({"alerts": alerts, "log_type": log_type})

@app.route("/dashboard")
def dashboard():
    init_session()
    history = session["history"]
    total = len(history)
    correct_count = sum(1 for h in history if h["result"] == "correct")
    incorrect_count = sum(1 for h in history if h["result"] == "incorrect")
    accuracy = (correct_count / total * 100) if total > 0 else 0
    
    # Calculate Streak
    streak = 0
    for h in reversed(history):
        if h["result"] == "correct":
            streak += 1
        else:
            break

    # Last 10
    recent = history[-10:]
    
    # Load scenarios for bilingual lookup
    scenarios, _, _ = load_training_data()
    
    return render_template("dashboard.html", 
                           history=history, 
                           accuracy=accuracy, 
                           recent=recent,
                           correct_count=correct_count,
                           incorrect_count=incorrect_count,
                           streak=streak,
                           scenarios=scenarios)

@app.route("/training", methods=["GET", "POST"])
def training():
    init_session()
    
    # State management: "question", "follow_up", "feedback"
    # We use query param or form hidden field for simple state, or implied by existence of result.
    
    scenarios, answers, feedback = load_training_data()
    lang = session["lang"]
    
    # GET: New Question (or Navigation)
    if request.method == "GET":
        # 1. Filter candidates by difficulty
        candidates = [sid for sid, s in scenarios.items() if s.get("difficulty") == session["difficulty"]]
        candidates.sort() # Stable order for "1/13" consistency
        
        if not candidates:
            # Fallback if no scenarios found for this difficulty
            candidates = list(scenarios.keys())
            candidates.sort()

        # 2. Initialize or Update Queue if Difficulty Changed
        # We store the queue identifiers to ensure consistency
        if "scenario_queue" not in session or session.get("queue_difficulty") != session["difficulty"]:
            session["scenario_queue"] = candidates
            session["queue_difficulty"] = session["difficulty"]
            session["current_index"] = 0
        
        # 3. Handle Navigation Actions
        # Sync session queue with current candidates in case file changed (optional but safe)
        if len(candidates) != len(session["scenario_queue"]):
             session["scenario_queue"] = candidates
             
        idx = session.get("current_index", 0)
        action = request.args.get("action")
        
        if action == "next":
            idx = min(idx + 1, len(candidates) - 1)
        elif action == "prev":
            idx = max(idx - 1, 0)
        
        # 4. Set Current Scenario
        session["current_index"] = idx
        # Ensure idx is within bounds (in case candidates shrank)
        if idx >= len(candidates):
            idx = 0
            session["current_index"] = 0
            
        scenario_id = candidates[idx]
        session["current_scenario"] = scenario_id
        
        # Reset transient state
        return render_template("training.html", 
                               scenario=scenarios[scenario_id], 
                               step="question", 
                               score=session["score"],
                               current_index=idx + 1,
                               total_scenarios=len(candidates))

    # POST: Answer Submission or Follow-up
    scenario_id = session.get("current_scenario")
    scenario = scenarios[scenario_id]

    # Recalculate context for the counter (since POST doesn't have it explicitly)
    candidates = [sid for sid, s in scenarios.items() if s.get("difficulty") == session["difficulty"]]
    candidates.sort()
    # Fallback same as GET
    if not candidates:
        candidates = list(scenarios.keys()); candidates.sort()
        
    current_idx = session.get("current_index", 0) + 1
    total_count = len(candidates)
    
    # Check if this is the Main Question answer or Follow-up answer
    if "choice" in request.form:
        # MAIN QUESTION
        user_choice = request.form.get("choice")
        correct_answer = answers[scenario_id]["classification"]
        
        # Determine correctness
        is_correct = (user_choice == correct_answer)
        
        # Scoring Logic (Difficulty Multiplier)
        diff_mult = {"Easy": 1, "Medium": 2, "Hard": 3}.get(scenario.get("difficulty", "Medium"), 1)
        
        session["score"]["total"] += 1
        if is_correct:
            session["score"]["correct"] += 1
            result = "correct"
            # History
            session["history"].append({
                "id": scenario_id, 
                "result": "correct", 
                "difficulty": scenario.get("difficulty"),
                "desc": get_text(scenario["attack_type"], lang)
            })
        else:
            session["score"]["incorrect"] += 1
            result = "incorrect"
            session["history"].append({
                "id": scenario_id, 
                "result": "incorrect", 
                "difficulty": scenario.get("difficulty"),
                "desc": get_text(scenario["attack_type"], lang)
            })
            
        session.modified = True
        
        # Check for Follow-up (Only if correct TP)
        has_followup = is_correct and (user_choice == "TRUE_POSITIVE") and ("follow_up" in answers[scenario_id])
        
        if has_followup:
            return render_template("training.html", 
                                   scenario=scenario, 
                                   result="correct", 
                                   step="follow_up", 
                                   follow_up_data=answers[scenario_id]["follow_up"],
                                   score=session["score"],
                                   current_index=current_idx,
                                   total_scenarios=total_count)
        
        # If no follow up, show final feedback
        return render_template("training.html", 
                               scenario=scenario, 
                               result=result, 
                               step="feedback", 
                               explanation=feedback[scenario_id][user_choice],
                               score=session["score"],
                               current_index=current_idx,
                               total_scenarios=total_count)

    elif "follow_up_choice" in request.form:
        # FOLLOW UP QUESTION
        user_choice = request.form.get("follow_up_choice")
        # Logic to check strict equality might be tricky with bilingual labels.
        # We assume the VALUE of the option is passed.
        
        # Find option
        options = answers[scenario_id]["follow_up"]["options"]
        selected_opt = next((o for o in options if get_text(o["label"], lang) == user_choice), None)
        
        if selected_opt and selected_opt.get("correct"):
             msg = "Excellent! That is the correct response."
        else:
             msg = "Not quite. Check the recommended actions."
             
        # Show final feedback
        # We need to know the original result to show the main feedback too
        prev_result = "TRUE_POSITIVE" # Implied
        
        return render_template("training.html", 
                               scenario=scenario, 
                               result="correct", 
                               step="feedback", 
                               explanation=feedback[scenario_id]["TRUE_POSITIVE"],
                               follow_up_msg=msg,
                               score=session["score"],
                               current_index=current_idx,
                               total_scenarios=total_count)

    return redirect(url_for("training"))

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False)
