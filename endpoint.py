from flask import Flask, render_template, request, redirect, url_for
import os
import threading

app = Flask(__name__)

@app.route('/')
def hello_world():
    return "RUNNING"

@app.route('/send', methods=['POST'])
def upload_file():
    for i in request.files:
        file = request.files[i]
        if file.filename != "":
            file.save(os.path.join("hc22000", file.filename))
    return redirect('/')

def http_endpoint(port):
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == "__main__":
    # Use threading to run Flask app and http_endpoint simultaneously
    threading.Thread(target=http_endpoint, args=(8080,), daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
