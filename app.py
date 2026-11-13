from flask import Flask, request, jsonify, send_from_directory, make_response
from http.cookies import SimpleCookie
import uuid
import base64
import json

app = Flask(__name__)

VALID_FLAGS = {}
VALID_COOKIES = []
FLAG_BASE = "flag"

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/cookies/<challenge>/authenticate', methods=['POST'])
def handle_cookies_authN(challenge):
    data = request.get_json(silent=True)
    
    res, msg = authenticate(data.get('username'), data.get('password'), challenge)
    if res == "OK":
        response = make_response(jsonify({
            "status": "success",
            "message": msg
        }), 200)
                        
        response.headers['Set-Cookie'] = generate_cookie(challenge)
        return response
    else:
        response = make_response(jsonify({
            "status": "failed",
            "message": msg
        }), 401)
        return response

@app.route('/cookies/<challenge>/authorise', methods=['POST'])
def handle_cookies_authZ(challenge):
    cookies = request.headers.get('Cookie')
    if cookies is None:
        res = make_response(jsonify({
            "status": "failed",
            "message": "`Cookie` header not present"
        }), 400)
        return res

    res, msg = authorise(challenge, cookies)
    if res == "OK":
        res = make_response(jsonify({
            "status": "success",
            "message": msg
        }), 200)
        return res
    else:
        res = make_response(jsonify({
            "status": "failed",
            "message": msg
        }), 403)
        return res

def authorise(challenge, cookie):
    status, msg = challengeN(challenge, cookie)
    return status, msg

def challengeN(challenge, cookie):
    jar = SimpleCookie()
    jar.load(cookie)

    if challenge[-1] == "1":
        m = jar.get("sessionid")
        if m and m.value in VALID_COOKIES:
            return "OK", generate_flag(challenge)
        return "ERR", f"Failed to obtain access to /{challenge}"
    elif challenge[-1] == "2":
        if jar.get("isAdmin") and jar["isAdmin"].value == "true":
            return "OK", generate_flag(challenge)
        return "ERR", f"Failed to obtain access to /{challenge}"
    elif challenge[-1] == "3":
        morsel = jar.get("data")
        if morsel is None:
            return "ERR", "Missing `data` cookie"
        try:
            decoded = base64.urlsafe_b64decode(morsel.value).decode("utf-8")
            user_cookie_dict = json.loads(decoded)
        except (ValueError, json.JSONDecodeError):
            return "ERR", "Malformed `data` cookie"

        if user_cookie_dict.get("role") == "admin":
            return "OK", generate_flag(challenge)
        return "ERR", f"Failed to obtain access to /{challenge}"
    else:
        return "ERR", f"Not done yet"

def authenticate(username, password, challenge):
    if((challenge[-1] != password[-1]) or (not challenge[-1].isdigit()) or (not password[-1].isdigit())):
        return "ERR", f"Could not authenticate user. Ensure you have the correct password for the correct challenge"

    if(username == "user"):
        return "OK", "Hello, Challenger"

    return "ERR", f"Could not authenticate user '{username}'"

def generate_cookie(challenge):
    if challenge.lower() == "challenge1":
        sid = str(uuid.uuid4())
        VALID_COOKIES.append(sid)
        return f"sessionid={sid}"
    elif challenge.lower() == "challenge2":
        return f"isAdmin=false"
    elif challenge.lower() == "challenge3":
        text = "{\"username\":\"user\",\"role\":\"user\"}"
        data = base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8")
        return f"data={data}"
    else:
        return None

def generate_flag(challenge):
    VALID_FLAGS.update({challenge: FLAG_BASE + f"{{{uuid.uuid4().hex}}}"})
    return VALID_FLAGS.get(challenge)

if __name__ == '__main__':
    app.run(debug=True)