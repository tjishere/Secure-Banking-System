from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes, random
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import socket
from Crypto.Protocol.KDF import HKDF
import hmac
import logging


localhost = '127.0.0.1'
portNum = 30000
logging.basicConfig(filename='client_audit.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def generate_nonce(length=8):
    return ''.join(str(random.randint(0,9)) for i in range(length))

#Function generates asymmetric RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Using a 2048-bit RSA key so signature is 256 bytes
def sign(message, private_key):
    # Hash the message first
    message_hash = SHA256.new(message)
    # Create a signature scheme object
    signer = pss.new(private_key)
    # Sign the message hash
    signature = signer.sign(message_hash)
    return signature

def verify(message, signature, public_key):
    # Hash the message first
    message_hash = SHA256.new(message)
    # Create a signature scheme object for verification
    verifier = pss.new(public_key)
    try:
        # Attempt to verify the signature
        verifier.verify(message_hash, signature)
        return True  # The signature is valid.
    except (ValueError, TypeError):
        return False  # The signature is not valid.
    
def gen_mac(keyMAC,data):
    return hmac.new(keyMAC, data, SHA256).digest()

def verify_mac(keyMAC,data,macSent):
    return hmac.compare_digest(gen_mac(keyMAC,data), macSent)
    

cli_private_key, cli_public_key = generate_rsa_keys()
# For responder B
rsa_public_key_a = RSA.import_key(cli_public_key)
rsa_private_key_a = RSA.import_key(cli_private_key)

def start_client(host = localhost, port = portNum):
    try:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.connect((host, port))
                # Initial key distribution of public keys of server and client

                server.send(rsa_public_key_a.exportKey())
                bank_public_key = server.recv(1024)
                rsa_public_key_b = RSA.import_key(bank_public_key)
                encryptor = PKCS1_OAEP.new(rsa_public_key_b)
                decryptor = PKCS1_OAEP.new(rsa_private_key_a)

                # 1) Sending client info to Bank Server
                send_user = input("Please enter your username: ")
                send_pass = input("Pleae enter your password: ")
                server.send(send_user.encode("UTF-8"))
                ack = server.recv(1024).decode("UTF-8")
                if ack != "ACK":
                    print("Error: No ACK receivedß")
                server.send(send_pass.encode("UTF-8"))

                # 2) Receive Nk1 and IDk encrypted with PUa
                encrypted_message1 = server.recv(1024)
                message1 = decryptor.decrypt(encrypted_message1)
                nonce1 = message1.decode("UTF-8")[:8]
                print(f"Encrypted message1: {encrypted_message1}")
                print(f"Decrypted message1: {message1}")
                print(f"Nonce Nk: {nonce1}")

                # 3) Send Na and Nk1 encrypted with PUk
                nonce2 = generate_nonce() # Na is nonce2
                message2 = nonce2 + nonce1
                encrypted_message2 = encryptor.encrypt(message2.encode("UTF-8"))
                server.send(encrypted_message2)

                # 4) Receive Nk1 encrypted with PUa
                encrypted_message3 = server.recv(1024)
                message3 = decryptor.decrypt(encrypted_message3)
                check_nonce1 = message3.decode("UTF-8")
                print(f"Encrypted message3: {encrypted_message3}")
                print(f"Decrypted message3: {message3}")
                print(f"Nonce Nk: {check_nonce1}")

                server.send("ACK".encode("UTF-8"))

                # 5) Receive master key Ka encrypted with PUa
                encrypted_message4 = server.recv(1024)
                print(f"Encrypted message4: {encrypted_message4}")
                master_key = decryptor.decrypt(encrypted_message4)
                print(f"Master key: {master_key}")

                #6) Test Deposit, withdraw, balance
                x = input("What would you like to do: ")
                if x == "deposit":
                    y = input("Amount: ")
                    server.send(x.encode("UTF-8"))
                    server.send(y.encode("UTF-8"))
                elif x == "withdraw":
                    y = input("Amount: ")
                    server.send(x.encode("UTF-8"))
                    server.send(y.encode("UTF-8"))
                elif x == "balance":
                    server.send(x.encode("UTF-8"))
                    z = server.recv(1024)
                    #encrypted_message5 = server.recv(1024)
                    #print(f"Encrypted message5: {encrypted_message5}")
                    #bal = decryptor.decrypt(encrypted_message5)
                    print(f"balance: {z}")
                 
                else:
                    print("Invalid action entered")
  
                
                ack = server.recv(1024).decode("UTF-8")
                if ack != "ACK":
                    print("Error: No ACK receivedß")
                
                
                """
                KDF to turn Master Key into Two AES keys (DataEncryption Key and MAC key)
                Master Key acts as both the Password and the Salt
                Both Client and Server will generate the Same Symmetric Key
                (or at least they should)
                Use the gen_mac function to generate MAC
                Use the cipher to encrypt and decrypt messages
                """
                keys = HKDF(master_key, 32, b"2024", hashmod=SHA256)
                keyDE = keys[:16]
                keyMAC = keys[16:]
                cipher = AES.new(keyDE, AES.MODE_EAX)
                print(f"Keys: {keys}")

		
                

    except KeyboardInterrupt:
        print("Client is closing.")
    finally:
        server.close()

if __name__ == "__main__":
    start_client()