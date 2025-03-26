import requests
from flask import Flask, render_template, request, redirect, url_for , session, jsonify
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def check_health():
    try:
        response = requests.get('https://vault-7-rebooted.vercel.app/check_health',timeout=5)
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

@app.route('/demo/url',methods=['GET','POST'])
def url_scan():
    return render_template('url_scan.html')

@app.route('/demo/message',methods=['GET','POST'])
def message_scan():
    return render_template('message_scan.html')

@app.route('/scan-file',methods=['POST'])
def scan_file():
    try:
        data = request.get_json()
        filename = data.get('filename')
        file_md5_hash = data.get('fileMd5Hash')

        # Get token from API with timeout
        token_response = requests.get('https://vault-7-rebooted.vercel.app/get_token', timeout=5)
        token = token_response.json()['token']

        # Send scan request with timeout
        scan_data = {
            "token": token,
            "hashes": [
                [filename, f"md5:{file_md5_hash}"]
            ]
        }

        scan_response = requests.post(
            'https://vault-7-rebooted.vercel.app/file_scan',
            json=scan_data,
            headers={'Content-Type': 'application/json'},
            timeout=10  # Increased timeout for scan request
        )

        scan_result = scan_response.json().get('result', [])

        if not scan_result:
            return jsonify({
                'error': 'Failed to query the backend',
                'result': [['Unknown', 'Unknown', 'error']],
                'filename': filename,
                'hash': file_md5_hash
            }), 500

        return jsonify({
            'result': scan_result,
            'filename': filename,
            'hash': file_md5_hash
        })

    except requests.Timeout:
        return jsonify({
            'error': 'Request timed out',
            'result': [['Unknown', 'Unknown', 'timeout']],
            'filename': filename,
            'hash': file_md5_hash
        }), 504
    except Exception as e:
        return jsonify({
            'error': str(e),
            'result': [['Unknown', 'Unknown', 'error']],
            'filename': filename,
            'hash': file_md5_hash
        }), 500

@app.route('/scan-url',methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url')

    token_response = requests.get('https://vault-7-rebooted.vercel.app/get_token')
    token = token_response.json()['token']

    scan_data = {
        "token": token,
        "url": url
    }

    scan_response = requests.post(
        'https://vault-7-rebooted.vercel.app/url_scan',
        json=scan_data,
        headers={'Content-Type': 'application/json'}
    )

    scan_result = scan_response.json()['result']

    if not scan_result:
        result = 'Failed to query the backend'
    else:
        result = scan_result

    final_result = jsonify({
        'result': result,
        'url': url
    })
    return final_result

@app.route('/scan-message',methods=['POST'])
def scan_message():
    data = request.get_json()
    message = data.get('message')
    
    token_response = requests.get('https://vault-7-rebooted.vercel.app/get_token')
    token = token_response.json()['token']

    scan_data = {
        "token": token,
        "message": message
    }

    scan_response = requests.post(
        'https://vault-7-rebooted.vercel.app/message_scan',
        json=scan_data,
        headers={'Content-Type': 'application/json'}
    )

    response_data = scan_response.json()

    # Sample Response
    # {'status': 'success', 'data': {'result': 'safe', 'reason': 'This message, "This is a test", contains no suspicious elements such as urgent action, links, requests for sensitive information, or poor grammar/spelling. It appears to be a simple test message, likely from a legitimate source. Therefore, I classify it as \'Safe\'.'}}
    
    if not response_data.get('data'):
        result = 'Failed to query the backend'
    else:
        result = {
            'result': response_data['data']['result'],
            'reason': response_data['data']['reason']
        }

    print(result)

    return jsonify({'result': result})

@app.route('/banner')
def banner():
    return render_template('banner.html')

@app.route('/others')
def others():
    return render_template('others.html')

if __name__ == '__main__':
    app.run(debug=True,port=5001)