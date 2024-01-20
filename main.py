# API Request Security PoC
# Michal Walkowski - https://mwalkowski.github.io/
# https://github.com/mwalkowski
#
# For RSA Signing Process: https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#name-rsassa-pkcs1-v1_5-using-sha

import re
import base64
import datetime
import queue
from functools import wraps

from flask import Flask
from flask import make_response as flask_make_response
from flask import jsonify
from flask import request
from requests import status_codes

from datetime import datetime, timezone

from Crypto.Signature import pkcs1_15 as pkcs_signature
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

PRIVATE_KEY_PATH = 'private.key'
PUBLIC_KEY_PATH = 'public.pem'
SIGNATURE_HEADER = 'X-Signature'
NONCE_HEADER = 'X-Nonce-Value'
NONCE_QUEUE_SIZE_LIMIT = 10
NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'
TIME_DIFF_TOLERANCE_IN_SECONDS = 10.0


PUBLIC_KEY = RSA.import_key(open(PUBLIC_KEY_PATH).read())
PRIVATE_KEY = RSA.import_key(open(PRIVATE_KEY_PATH).read())
UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"

received_nonces = queue.Queue()
app = Flask(__name__)


def check_headers_exists():
    if NONCE_HEADER not in request.headers:
        return NONCE_HEADER
    if NONCE_CREATED_AT_HEADER not in request.headers:
        return NONCE_CREATED_AT_HEADER
    if SIGNATURE_HEADER not in request.headers:
        return SIGNATURE_HEADER
    return None


def is_nonce_created_at_correct():
    try:
        nonce_created_at = request.headers[NONCE_CREATED_AT_HEADER]
        time_diff = datetime.now().astimezone(timezone.utc) - \
                    datetime.fromisoformat(nonce_created_at)
        return time_diff.total_seconds() < TIME_DIFF_TOLERANCE_IN_SECONDS
    except Exception:
        return False


def clean_up_the_received_nonces_queue():
    if received_nonces.qsize() >= NONCE_QUEUE_SIZE_LIMIT:
        received_nonces.get(block=True)


def is_nonce_correct():
    nonce = request.headers[NONCE_HEADER]
    if re.match(UUID_PATTERN, nonce) and nonce not in received_nonces.queue:
        clean_up_the_received_nonces_queue()
        received_nonces.put(nonce, block=True)
        return True
    return False


def verify(message, signature):
    h = SHA256.new(message)
    try:
        pkcs_signature.new(PUBLIC_KEY).verify(h, base64.standard_b64decode(signature))
    except (ValueError, TypeError) as e:
        return False
    return True


def is_signature_correct():
    nonce_value = request.headers[NONCE_HEADER]
    nonce_created_at = request.headers[NONCE_CREATED_AT_HEADER]
    signature_input = "{}{}{}{}{}".format(request.method, request.path, nonce_value,
                                          nonce_created_at, request.data.decode())
    signature_input_b64 = base64.standard_b64encode(signature_input.encode())
    return verify(signature_input_b64, request.headers[SIGNATURE_HEADER])


def make_response(msg):
    return flask_make_response(jsonify({"error": msg}), status_codes.codes.forbidden)


def signature_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        missing_header = check_headers_exists()

        if missing_header:
            return make_response(f"Missing header: {missing_header}")

        if not is_nonce_correct():
            return make_response("Nonce is already used or incorrect")

        if not is_nonce_created_at_correct():
            return make_response("The request is time-barred")

        if not is_signature_correct():
            return make_response("Invalid Signature")

        return f(*args, **kwargs)
    return decorator


@app.route("/signed-body", methods=["POST"])
@signature_required
def signed_body():
    return jsonify({"msg": "Ok!"})


if __name__ == "__main__":
    app.run()
