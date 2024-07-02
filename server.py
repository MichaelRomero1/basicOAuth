from flask import Flask, abort, jsonify, redirect, request, session, render_template
from dotenv import load_dotenv
import dotenv
import os
import uuid
import mysql.connector
import pathlib
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2 import id_token
import google.auth.transport.requests
import pip._vendor.cachecontrol as cachecontrol  # Import cachecontrol
import time


dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

#load env vars
load_dotenv()

#google oauth stuffs
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, 'client_secrets.json')


flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid'],
    redirect_uri= os.getenv('REDIRECT_URI'))

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if 'google_id' not in session:  # Check if the user is logged in
            return abort(401)  # If not, return 401 Unauthorized
        else:
            return function(*args, **kwargs)
        
    return wrapper

@app.route('/quiz')
@login_is_required
def quiz():
    user_name = session.get('name')
    return render_template("quiz.html", user_name=user_name)

# Redirect user to Google content screen
@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

# Receive data from Google endpoint
@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session['state'] == request.args['state']:
        print(session['state'])
        print(request.args['state'])
        return abort(500)  # State does not match!
    
    credentials = flow.credentials
    request_session = flow.authorized_session()
    cached_session = cachecontrol.CacheControl(request_session)  # Use cachecontrol
    token_request = google.auth.transport.requests.Request(session=cached_session)


    return redirect('/quiz')

@app.route('/')
def index():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True, port=8000, host="0.0.0.0")