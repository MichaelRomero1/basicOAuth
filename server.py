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
from flask_session import Session
import redis


dotenv.load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Set up Redis for session storage
app.config['SESSION_TYPE'] = 'redis'  # Use Redis to store session data
app.config['SESSION_PERMANENT'] = False  # Make sessions non-permanent (expire on browser close)
app.config['SESSION_USE_SIGNER'] = True  # Sign session cookies for extra security
app.config['SESSION_KEY_PREFIX'] = 'session:'  # Prefix for session keys in Redis
app.config['SESSION_REDIS'] = redis.StrictRedis(host='localhost', port=6379, db=0)  # Redis connection details
Session(app)  # Initialize the session extension

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

# Clear login session from the user
@app.route('/logout') 
def logout():
    #session.clear()
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/')

# Receive data from Google endpoint
@app.route('/callback')
def callback():

    state_in_session = session.get('state')
    state_in_request = request.args.get('state')

    if not state_in_session == state_in_request:
        print(state_in_session)
        print(state_in_request)
        return abort(500)  # State does not match!
    
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    request_session = flow.authorized_session()
    cached_session = cachecontrol.CacheControl(request_session)  # Use cachecontrol
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=10)
    
    session['google_id'] = id_info.get('sub')
    session['name'] = id_info.get('name')
    session['email'] = id_info.get('email')

    return redirect('/quiz')

@app.route('/')
def index():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(debug=True, port=8000, host="0.0.0.0")