# API Request Security PoC
# Michal Walkowski - https://mwalkowski.github.io/
# https://github.com/mwalkowski
#

import base64
import datetime
import json
import uuid

import pytest

from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15 as pkcs_signature
from Crypto.Cipher import PKCS1_v1_5 as pkcs_cipher

from main import app as test_app, received_nonces, PRIVATE_KEY, PUBLIC_KEY
from main import NONCE_HEADER, NONCE_CREATED_AT_HEADER, SIGNATURE_HEADER, TIME_DIFF_TOLERANCE_IN_SECONDS

@pytest.fixture()
def app():
    test_app.config.update({
        "TESTING": True,
    })
    yield test_app



@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


def test_NONCE_HEADER_not_exists(client):
    response = client.post("/signed-body", json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {NONCE_HEADER}'}


def test_NONCE_CREATED_AT_HEADER_not_exists(client):
    response = client.post("/signed-body", headers={NONCE_HEADER: "a"}, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {NONCE_CREATED_AT_HEADER}'}


def test_SIGNATURE_HEADER_not_exists(client):
    headers = {
        NONCE_HEADER: "a",
        NONCE_CREATED_AT_HEADER: "b",
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {SIGNATURE_HEADER}'}


def test_NONCE_HEADER_is_incorrect(client):
    headers = {
        NONCE_HEADER: "a",
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "Nonce is already used or incorrect"}


def test_NONCE_HEADER_pool(client):
    for _ in range(30):
        headers = {
            NONCE_HEADER: uuid.uuid4(),
            NONCE_CREATED_AT_HEADER: "b",
            SIGNATURE_HEADER: "aaaa"
        }
        response = client.post("/signed-body", headers=headers, json={})

        assert response.status_code == 403
    assert received_nonces.qsize() == 10


def test_NONCE_HEADER_is_duplicated(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "Nonce is already used or incorrect"}


def test_NONCE_CREATED_AT_HEADER_invalid(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

def test_NONCE_CREATED_AT_HEADER_time_barred(client):
    nonce_created_at = datetime.datetime.now(datetime.timezone.utc)
    nonce_created_at -= datetime.timedelta(days=0, seconds=TIME_DIFF_TOLERANCE_IN_SECONDS + 1)
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: nonce_created_at.isoformat(),
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

def test_SIGNATURE_invalid(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={'msg': 'msg'})

    assert response.status_code == 403
    assert response.json == {'error': "Invalid Signature"}


def test_SIGNATURE_ok(client):
    nonce = uuid.uuid4()
    nonce_created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    request_data = json.dumps({'msg': 'msg'})

    signature_input = "{}{}{}{}{}".format('POST', '/signed-body', nonce, nonce_created_at, request_data)
    signature_input_b64 = base64.standard_b64encode(signature_input.encode())
    h = SHA256.new(signature_input_b64)
    signature = base64.standard_b64encode(pkcs_signature.new(PRIVATE_KEY).sign(h)).decode('utf-8')

    headers = {
        NONCE_HEADER: nonce,
        NONCE_CREATED_AT_HEADER: nonce_created_at,
        SIGNATURE_HEADER: signature
    }
    response = client.post("/signed-body", headers=headers, json=json.loads(request_data))

    assert response.status_code == 200
    assert response.json == {"msg": "Ok!"}




def test_encrypted_body_ok(client):
    msg = {'name': 'Michal'}
    msg_b64 = base64.standard_b64encode(json.dumps(msg).encode())
    encrypted_msg = {
        'encryptedPayload': base64.standard_b64encode(pkcs_cipher.new(PUBLIC_KEY).encrypt(msg_b64)).decode()
    }

    response = client.post("/encrypted-body", json=encrypted_msg)

    assert response.status_code == 200
    assert response.json == {"msg": "Hello Michal"}


def test_encrypted_body_nok(client):
    msg = {'name': 'Michal'}
    msg_b64 = base64.standard_b64encode(json.dumps(msg).encode())
    encrypted_msg = {
        'encryptedPayload': msg_b64.decode()
    }

    response = client.post("/encrypted-body", json=encrypted_msg)

    assert response.status_code == 403
    assert response.json == {"error": "Decryption problem"}


def test_signed_encrypted_body_ok(client):
    msg = {'name': 'Michal'}
    msg_b64 = base64.standard_b64encode(json.dumps(msg).encode())
    encrypted_msg = {
        'encryptedPayload': base64.standard_b64encode(pkcs_cipher.new(PUBLIC_KEY).encrypt(msg_b64)).decode()
    }

    nonce = uuid.uuid4()
    nonce_created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    request_data = json.dumps(encrypted_msg)

    signature_input = "{}{}{}{}{}".format('POST', '/signed-body', nonce, nonce_created_at, request_data)
    signature_input_b64 = base64.standard_b64encode(signature_input.encode())
    h = SHA256.new(signature_input_b64)
    signature = base64.standard_b64encode(pkcs_signature.new(PRIVATE_KEY).sign(h)).decode('utf-8')

    headers = {
        NONCE_HEADER: nonce,
        NONCE_CREATED_AT_HEADER: nonce_created_at,
        SIGNATURE_HEADER: signature
    }

    response = client.post("/encrypted-body", headers=headers, json=encrypted_msg)

    assert response.status_code == 200
    assert response.json == {"msg": "Hello Michal"}