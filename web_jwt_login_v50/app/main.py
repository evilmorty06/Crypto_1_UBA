from flask import Flask
from flask import render_template
from flask import make_response
from flask import request
from flask import redirect
from flask import url_for
from datetime import datetime
from Crypto.PublicKey import RSA
from authlib.jose import jwt
import os


private_key = RSA.generate(1024)
app = Flask(__name__)
app.config.update({
    'PRIVATE_KEY': private_key.export_key(),
    'PUBLIC_KEY': private_key.publickey().export_key()
})


def generate_token(username):
    return jwt.encode(
        {'alg': 'RS256'},
        {'username': username, 'is_admin': False, 'iat': datetime.utcnow()},
        app.config.get('PRIVATE_KEY')
    ).decode()


def decode_token(token):
    try:
        return jwt.decode(token, app.config.get('PUBLIC_KEY'))
    except:
        return None


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username') or 'guest'
    token = generate_token(username)
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('token', token)
    return resp


@app.route('/', methods=['GET'])
def index():
    token = request.cookies.get('token')
    if token is None:
        return render_template('index.html')
    
    data = decode_token(token)
    if data is None:
        return render_template('index.html', error='Error: invalid token')
    
    if data.get('is_admin'):
        return render_template('index.html', flag=os.getenv('FLAG'))
    
    username = data.get('username')
    return render_template('index.html', message=f'Welcome {username}!')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
