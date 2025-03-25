import requests
from flask import Flask, render_template, request, redirect, url_for , session, jsonify
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def check_health():
    try:
        response = requests.get('https://vault-7-rebooted.vercel.app/check_health')
        data = response.json()
        if data.get('status') == 'ok':
            return 'Operational'
        else:
            return 'Offline'
    except:
        return 'Offline'

@app.route('/')
def base():
    return render_template('base.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/status')
def status():
    current_time = datetime.now().strftime('%B %d, %Y %H:%M UTC')
    health_status = check_health()
    print(health_status)
    return render_template('status.html', current_time=current_time, health_status=health_status)

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email == 'admin@admin.com' and password == 'admin':
            session['email'] = email
            return redirect(url_for('get_started'))
        else:
            return render_template('signin.html',error='Invalid email or password')
    return render_template('signin.html')

@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        return render_template('signup.html',error='Registration service is offline for now please try again later')
    return render_template('signup.html')

@app.route('/get-started')
def get_started():
    if 'email' in session:
        return render_template('get_started.html')
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('base'))

@app.route('/<path:path>')
def error(path):
    return render_template('error.html')

@app.route('/demo',methods=['GET','POST'])
def demo():
    if request.method == 'POST':
        pass
    else:
        return render_template('demo.html')

@app.route('/demo/file',methods=['GET','POST'])
def file_scan():
    return render_template('file_scan.html')

@app.route('/scan-file',methods=['POST'])
def scan_file():
    data = request.get_json()
    filename = data.get('filename')
    file_md5_hash = data.get('fileMd5Hash')

    # Get token from API
    token_response = requests.get('https://vault-7-rebooted.vercel.app/get_token')
    token = token_response.json()['token']

    # Send scan request
    scan_data = {
        "token": token,
        "hashes": [
            [filename, f"md5:{file_md5_hash}"]
        ]
    }

    scan_response = requests.post(
        'https://vault-7-rebooted.vercel.app/file_scan',
        json=scan_data,
        headers={'Content-Type': 'application/json'}
    )

    scan_result = scan_response.json()['result']

    if not scan_result:
        result = 'File is safe'
    else:
        result = scan_result

    final_result = jsonify({
        'result': result,
        'filename': filename,
        'hash': file_md5_hash
    })
    print('--------------------------------')
    print(final_result)
    return final_result

if __name__ == '__main__':
    app.run(debug=True)
