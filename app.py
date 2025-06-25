from flask import Flask, render_template, request
import hashlib, base64

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ip')
def ip_lookup():
    ip = request.remote_addr
    return render_template('ip_lookup.html', ip=ip)

@app.route('/password', methods=['GET', 'POST'])
def password_checker():
    strength = None
    password = ''
    if request.method == 'POST':
        password = request.form['password']
        if len(password) >= 12:
            strength = "Very Strong 💪"
        elif len(password) >= 8:
            strength = "Strong ✅"
        elif len(password) >= 5:
            strength = "Medium ⚠️"
        else:
            strength = "Weak ❌"
    return render_template('password_checker.html', strength=strength, password=password)

@app.route('/hash', methods=['GET', 'POST'])
def hash_generator():
    result = None
    if request.method == 'POST':
        text = request.form['text']
        method = request.form['method']
        if method == 'md5':
            result = hashlib.md5(text.encode()).hexdigest()
        elif method == 'sha1':
            result = hashlib.sha1(text.encode()).hexdigest()
        elif method == 'sha256':
            result = hashlib.sha256(text.encode()).hexdigest()
    return render_template('hash_generator.html', result=result)

@app.route('/base64', methods=['GET', 'POST'])
def base64_tool():
    result = ''
    if request.method == 'POST':
        text = request.form['text']
        action = request.form['action']
        try:
            if action == 'encode':
                result = base64.b64encode(text.encode()).decode()
            elif action == 'decode':
                result = base64.b64decode(text.encode()).decode()
        except:
            result = "Invalid base64 input!"
    return render_template('base64_tool.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
