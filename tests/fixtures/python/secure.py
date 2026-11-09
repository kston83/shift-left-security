"""Secure counterpart of insecure.py: must produce no findings."""
import hashlib
import subprocess

import flask
import requests
import yaml

app = flask.Flask(__name__)
ALLOWED_HOSTS = {"localhost"}


@app.route("/run")
def run():
    subprocess.run(["ping", "-c", "1", "localhost"], check=True, timeout=5)
    return "ok"


@app.route("/fetch")
def fetch():
    return requests.get("https://example.com/status", timeout=5).text


def strong_hash(data):
    return hashlib.sha256(data).hexdigest()


def load(doc):
    return yaml.safe_load(doc)


if __name__ == "__main__":
    app.run()
