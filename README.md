## API Request Security PoC
This Proof of Concept (PoC) code demonstrates a simple implementation of API request security using RSA signatures and nonces. The code is written in Python and utilizes the Flask framework. This code is mentioned in article mentioned [here](https://mwalkowski.github.io/post/using-burp-python-scripts-to-sign-requests-with-rsa-keys/).

###  Prerequisites
Before running the code, ensure that you have the following:
*  Python installed on your system, and:
```bash
virtual env venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### How to Run
Run the Flask application using the following command:
```bash
python3 main.py
```

### Endpoints
1. /signed-body - Signed Request  
Method: POST   
Headers:  
X-Signature: RSA signature of the request   
X-Nonce-Value: Nonce value  
X-Nonce-Created-At: Nonce creation timestamp  
Body: Any JSON payload  
This endpoint verifies the integrity of the request using RSA signatures.  

### Testing
Use tools like curl or Postman to send requests to the specified endpoints. Ensure that you include the required headers for each endpoint.

### Disclaimer
This code is a simplified example for educational purposes and may not cover all aspects of a production-grade implementation. It is recommended to enhance security measures based on specific application requirements.
