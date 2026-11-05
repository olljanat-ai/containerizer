from flask import Flask
app = Flask(__name__)

@app.get("/health")
def h():
    return "ok"
