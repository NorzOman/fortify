

from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime

app = Flask(__name__)

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
    return render_template('status.html', current_time=current_time)

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


if __name__ == '__main__':
    app.run(debug=True)
