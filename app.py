from flask import Flask, url_for, redirect, session
from authlib.integrations.flask_client import OAuth
import os
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

# OAUTH CONFIG
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'},
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
    clock_skew_in_seconds = 10
)


@app.route('/')
# Add login required if you wanted
def hello_world():
    email = dict(session).get('email', None) # Get the email from the session, set to None if not found
    return f'Hello, {email}!'


@app.route('/login')
def login():
    google = oauth.create_client('google') # Create/get the google client above
    redirect_uri = url_for('authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google') # Create/get the google client above
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    user_info = resp.json()
    # Do something with the token and profile
    session['email'] = user_info['email']
    return redirect('/')


@app.route('/logout')
def logout():
    for key in list(session.keys()): # Loop through all keys in the session and remove them
        session.pop(key)
    return redirect('/')

 
if __name__ == '__main__':
    app.run(debug=True, port=8000, host="0.0.0.0")
    