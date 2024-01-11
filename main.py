import base64
import json

from flask import Flask
from flask import jsonify
from flask import request

from Crypto.Signature import pkcs1_15 as pkcs_signature
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_v1_5 as pkcs_cipher
from Crypto.PublicKey import RSA

PRIV_KEY = 'private.key'
PUB_KEY = 'public.pem'
SIGNATURE_HEADER = 'X-Signature'
NONCE_HEADER = 'X-Nonce-Value'
NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'

app = Flask(__name__)


def check_headers_exists():
    if SIGNATURE_HEADER not in request.headers:
        return SIGNATURE_HEADER
    if NONCE_HEADER not in request.headers:
        return NONCE_HEADER
    if NONCE_CREATED_AT_HEADER not in request.headers:
        return NONCE_CREATED_AT_HEADER
    return None


def verify(message, signature):
    h = SHA256.new(message)
    pkey = RSA.import_key(open(PRIV_KEY).read())

    print('SIGNATURE EXPECTED', base64.standard_b64encode(pkcs_signature.new(pkey).sign(h)).decode('utf-8'))
    print('SIGNATURE RECEIVED', signature)

    key = RSA.import_key(open(PUB_KEY).read())
    try:
        pkcs_signature.new(key).verify(h, base64.standard_b64decode(signature))
    except (ValueError, TypeError) as e:
        print(e)
        return False
    return True


def check_signature():
    nonce_value = request.headers[NONCE_HEADER]
    nonce_created_at = request.headers[NONCE_CREATED_AT_HEADER]
    signature_input = "{}{}{}{}{}".format(request.method, request.path, nonce_value, nonce_created_at, request.data.decode())
    print('signature_input', signature_input)
    signature_input_b64 = base64.standard_b64encode(signature_input.encode()).decode()
    print('signature_input_b64', signature_input_b64)
    return verify(signature_input_b64.encode(), request.headers[SIGNATURE_HEADER])


@app.route("/signed-body", methods=["POST"])
def signed_body():
    missing_header = check_headers_exists()

    if missing_header:
        return jsonify({"error": f"Missing header: {missing_header}"})

    signature_ok = check_signature()
    if not signature_ok:
        return jsonify({"error": f"Invalid Signature"})

    return jsonify({"msg": "Ok!"})


if __name__ == "__main__":
    app.run()
