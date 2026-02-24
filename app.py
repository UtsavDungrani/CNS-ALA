from pathlib import Path
import subprocess
import sys

from flask import Flask, render_template, request

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent

ALA_CONFIG = {
    1: {
        "title": "ALA - 1",
        "script": "ALA1.py",
        "fields": [
            {"name": "message", "label": "Enter message to sign", "placeholder": "Hello world"},
            {"name": "tampered", "label": "Enter tampered message", "placeholder": "Hello wor1d"},
        ],
    },
    2: {
        "title": "ALA - 2",
        "script": "ALA2.py",
        "fields": [
            {"name": "msg1", "label": "Enter original message", "placeholder": "network security"},
            {"name": "msg2", "label": "Enter modified message", "placeholder": "network secur1ty"},
        ],
    },
    3: {
        "title": "ALA - 3",
        "script": "ALA3.py",
        "fields": [
            {"name": "send_message", "label": "Enter message to send", "placeholder": "confidential data"},
            {"name": "received_message", "label": "Enter received message", "placeholder": "confidential data"},
            {"name": "received_mac", "label": "Enter received MAC", "placeholder": "paste mac from sender output"},
        ],
    },
}


@app.get("/")
def home():
    return render_template("index.html")


@app.route("/ala/<int:ala_id>", methods=["GET", "POST"])
def ala_page(ala_id: int):
    config = ALA_CONFIG.get(ala_id)
    if not config:
        return "ALA page not found", 404

    output = ""
    values = {field["name"]: "" for field in config["fields"]}

    if request.method == "POST":
        values = {field["name"]: request.form.get(field["name"], "") for field in config["fields"]}
        output = run_ala_script(config["script"], [values[field["name"]] for field in config["fields"]])

    return render_template(
        "ala.html",
        ala_id=ala_id,
        title=config["title"],
        fields=config["fields"],
        values=values,
        output=output,
    )


def run_ala_script(script_name: str, inputs: list[str]) -> str:
    script_path = BASE_DIR / script_name
    if not script_path.exists():
        return f"Error: script '{script_name}' not found."

    stdin_data = "\n".join(inputs) + "\n"

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            input=stdin_data,
            text=True,
            capture_output=True,
            timeout=30,
            cwd=BASE_DIR,
        )
    except subprocess.TimeoutExpired:
        return "Error: program execution timed out."
    except Exception as exc:
        return f"Error running script: {exc}"

    combined_output = (result.stdout or "")
    if result.stderr:
        combined_output += "\n[stderr]\n" + result.stderr

    return combined_output.strip() or "No output returned by script."


if __name__ == "__main__":
    app.run(debug=True)
