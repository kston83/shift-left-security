"""Intentionally vulnerable test data for slsec-sast. Do not use."""
import hashlib
import os
import ssl
import subprocess

import flask
import requests
import yaml

app = flask.Flask(__name__)


@app.route("/run")
def run():
    host = flask.request.args.get("host")
    os.system("ping " + host)  # command injection
    subprocess.call("ls " + host, shell=True)  # shell=True
    return "ok"


@app.route("/fetch")
def fetch():
    url = flask.request.args.get("url")
    return requests.get(url).text  # SSRF


@app.route("/calc")
def calc():
    expr = flask.request.args.get("expr")
    return str(eval(expr))  # eval injection


def weak_hash(data):
    return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()


def load(doc):
    return yaml.load(doc, Loader=yaml.Loader)  # unsafe deserialization


def no_tls_verify(sock):
    ctx = ssl._create_unverified_context()
    ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)
    return ctx


if __name__ == "__main__":
    app.run(debug=True)
