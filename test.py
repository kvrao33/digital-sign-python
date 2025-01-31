from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

def load_public_key(key_input):
    """Load public key using pycryptodome"""
    try:
        # Load key from PEM format (it can be '-----BEGIN PUBLIC KEY-----' format)
        return RSA.import_key(key_input)
    except ValueError:
        raise ValueError("Invalid public key format")

def load_private_key(key_input):
    """Load private key using pycryptodome"""
    try:
        # Load key from PEM format (it can be '-----BEGIN PRIVATE KEY-----' format)
        return RSA.import_key(key_input)
    except ValueError:
        raise ValueError("Invalid private key format")

def sign_message(message, private_key):
    """Sign a message using the private key"""
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(message, signature, public_key):
    """Verify the signature using the public key"""
    h = SHA256.new(message.encode())
    signature = base64.b64decode(signature)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example usage
public_key_input = """-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB44zWkQb/rSW+3A/B4vJTp
Rc2mvii9xjbyuqrw7r0JH0K2cvbZcWcjkCGarcQq3UV4WOhCG4WUGHDwrEq21leh
4o6MnIXIAimrQbJXJG+Pfvvy+KoutsS69BQ0MHxraXEvke/Pk2wxNChyUgOLizg8
mkLU8y3WOW2FJMCtIiFvSAUNLUbZcuhCz02me5cFxXAekS1Cu5pJY1ZZkRgInLlL
MAjGqgbw0Y/Z4zrmSOBmaK0hmXCXb5ciyrIX2qz17h4rSZctht76L8UuBzkT3e5s
2T8Uug9d3kPj2EzthCXpp1Ouzg5ImYE3A3C9jMsjtBXXS92PQoHfPTvkkIYOdj1d
AgMBAAE=
-----END PUBLIC KEY-----"""

private_key_input = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQB44zWkQb/rSW+3A/B4vJTpRc2mvii9xjbyuqrw7r0JH0K2cvbZ
cWcjkCGarcQq3UV4WOhCG4WUGHDwrEq21leh4o6MnIXIAimrQbJXJG+Pfvvy+Kou
tsS69BQ0MHxraXEvke/Pk2wxNChyUgOLizg8mkLU8y3WOW2FJMCtIiFvSAUNLUbZ
cuhCz02me5cFxXAekS1Cu5pJY1ZZkRgInLlLMAjGqgbw0Y/Z4zrmSOBmaK0hmXCX
b5ciyrIX2qz17h4rSZctht76L8UuBzkT3e5s2T8Uug9d3kPj2EzthCXpp1Ouzg5I
mYE3A3C9jMsjtBXXS92PQoHfPTvkkIYOdj1dAgMBAAECggEACGujL+bYjHYYDwJ6
PJ6+LKWNFqFGSznEWBICmDe4+SqxRe4qHalViteeT5zs/iNdlG10+C3clx1AuLL3
nVa+0errDQZWF0F3T5OK7aD/GFq7CAikKg7XE0KvKZd7AyxcEvkyYB4fuims65Gk
55Jx/16raxPpTHPBmjWeKjEnbQ3ZXhzBR6uWKLY3dKzKfsLM/H8CIZ4VjceT29no
ecNUswVIUoeZa+oQ9fposstFHCwMor0BGpfSYv8zN1xUacDlTIWe0BeSzgsXCQH7
nleXtLQPUsbT8O6G4byEKxl1LctHK1sVpu6L20u5lirxc3hwnGXLXvDg/3XT6DlY
wg7PAQKBgQDPMEe66C2K1RrWW4FyxhTmaw4nVMA3bAPb6Q01vA6PbqCrgrTWd0O7
GbNjSKaI1wSeUUaWuSbhVEsiRvNaSjtyz1yhv48dHpY2TOKGDYDq+dVA+yrrHClP
BXNztugdkvAgIcoX0pIrPf6zYg/FlfBTmlD0Bl9cqObIFboe0Db1QQKBgQCVXgoW
i6neKzr9Yi4Powt0tgkg7K4Zk8pF0EE+dH6MNES0QRol5zeIXmuyT9rDQ0hr+QBB
d/G7piUJ3kadFSo6ABKuVnL34hxivWuMQZIeEfTLMHymxAIE8tckfiGKbXVBMtOQ
9RecTfIEFC6zbl3b4Bc+u7yfY5pmO+WLq/Y1HQKBgAhJOQUrle6weSNLg5DQhTN1
4poGFK3ivwDDgEi+3aI03W4eixbsrCPGclstI6PjXYbrXzRV8U0fruWPCtp4j4oW
6vB5FcMnXwCK8KBF1/sNxM6VfPDsLma/pA9jqELOhpXyY/+x5zCdiRspd9ICHhtp
14T64EN3actkuw3Sa/BBAoGACTprIyNz1j8TgO4c7GhlX8uTWs5knz3rRE7uiP5H
hz//cqeHBwp2+tziiHy4hlHU2p7irijL7Y0BQs/RywiwuC6i+NRse/YjTNJpH5w5
e9QeLKONP/xiJ44dTqrgRZ4nnWSXf6A02jpSln/strc940TACucsayiLNH/E2dFA
/90CgYEAuwIl9+Uw/QsPyrDb8Acv5ViKh5KbaigWfmb5WsUJgcbY58iDtHIBQCKG
LmuhSoH9O92FfIZ0CMGO5DtMExCe8wfw2Pdo/F0qGq0qKtdAhPYxS1fxxUl+q3DZ
EcKQLZ9uU894NB9EKWLSk9M2o+J/V3vU8vxuWWK0wedw1wNU2sw=
-----END RSA PRIVATE KEY-----"""

message = "This is a secret message"

public_key = load_public_key(public_key_input)
private_key = load_private_key(private_key_input)

# Signing
signature = sign_message(message, private_key)
print("Signature:", signature)

# Verifying
is_valid = verify_signature(message, signature, public_key)
if is_valid:
    print("Signature is valid")
else:
    print("Signature is invalid")
