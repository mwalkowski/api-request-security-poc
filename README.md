## API Request Security PoC
### Michal Walkowski - [Visit my blog](https://mwalkowski.github.io/post)
This repository contains a Proof of Concept (PoC) demonstrating API request security mechanisms implemented using RSA encryption and signatures.


### Implementation Overview
* RSA Encryption: The content of API requests is encrypted using the recipient's public key, ensuring confidentiality.
* Signatures: Each request is accompanied by a signature, allowing for verification of message integrity and origin.
* Protection against replay attacks: Nonce headers (X-Nonce-Value and X-Nonce-Created-At) protect against the re-sending of the same request.

### Code Structure
* `private.key` and `public.pem`: RSA keys used for encryption and decryption.  
* `main.py`: Python script containing the Flask application implementing the security mechanisms.
* `tests.py`: Tests

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
1. **/signed-body - Signed Request**  
**Method:** POST  
**Headers:**
   * X-Signature: RSA signature of the request  
   * X-Nonce-Value: Nonce value  
   * X-Nonce-Created-At: Nonce creation timestamp  

   **Body:** Any JSON payload  
   **Description:** This endpoint verifies the integrity of the request using RSA signatures.
   

2. **/encrypted-body - Encrypted Request**  
   **Method:** POST  
   **Headers:** None  
   **Body:** JSON payload with 'encryptedPayload' containing the encrypted message  
   **Description:** This endpoint decrypts the encrypted payload using RSA private key.


3. **/signed-encrypted-body - Signed and Encrypted Request**  
   **Method:** POST  
   **Headers:**
      * X-Signature: RSA signature of the request    
      * X-Nonce-Value: Nonce value  
      * X-Nonce-Created-At: Nonce creation timestamp  

   **Body:** JSON payload with 'encryptedPayload' containing the encrypted message  
   **Description:** This endpoint verifies the integrity of the request using RSA signatures and decrypts the encrypted payload.

4. **/encrypted-req-resp-signed - Signed and Encrypted Request, Encrypted Response**  
   **Method:** POST  
   **Headers:**
      * X-Signature: RSA signature of the request    
      * X-Nonce-Value: Nonce value  
      * X-Nonce-Created-At: Nonce creation timestamp  

   **Body:** JSON payload with 'encryptedPayload' containing the encrypted message  
   **Description:** This endpoint verifies the integrity of the request using RSA signatures and decrypts the encrypted payload.

### Usage
Send API requests to the specified endpoints using appropriate headers and payload.
Use the provided Flask routes for testing different security mechanisms.

### Disclaimer
This code is a simplified example for educational purposes and may not cover all aspects of a production-grade implementation. It is recommended to enhance security measures based on specific application requirements.
