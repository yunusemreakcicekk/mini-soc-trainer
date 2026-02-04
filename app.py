import os
from flask import Flask, render_template, request
from parsers.log_type_detector import detect_log_type
from parsers.linux_auth import parse_linux_auth_log
from parsers.web_access import parse_web_access_log
from detection.brute_force import detect_brute_force
from detection.web_recon import detect_web_recon

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def analyze_log(file_path):
    log_type = detect_log_type(file_path)

    if log_type == "linux_auth":
        events = parse_linux_auth_log(file_path)
        alerts = detect_brute_force(events)
        return alerts, log_type

    elif log_type == "web_access":
        events = parse_web_access_log(file_path)
        alerts = detect_web_recon(events)
        return alerts, log_type

    return [], log_type


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("logfile")
    if not file:
        return render_template("analyze.html", error="No file uploaded")

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    alerts, log_type = analyze_log(file_path)

    return render_template(
        "analyze.html",
        alerts=alerts,
        log_type=log_type
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

