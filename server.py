from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes, random
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import socket
import threading
from Crypto.Protocol.KDF import PBKDF2
import hmac

localhost = '127.0.0.1'
portNum = 30000 

class Client:
    def __init__(self, username, password, balance=None):
        self.username = username
        self.password = password
        self.balance = balance

    def __str__(self):
        return f"{self.username}, balance: {self.balance}"
    
    def deposit(self, deposit_amount):
        self.balance += deposit_amount
        return self.balance

    def withdraw(self, withdraw_amount):
        self.balance -= withdraw_amount
        return self.balance

    def bal_inquiry(self):
        return self.balance

def generate_nonce(length=8):
    return ''.join(str(random.randint(0,9)) for i in range(length))

#Function generates asymmetric RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

#Function to Generate MAC using MAC key + msg
def gen_mac(keyMAC, msg):
    return hmac.new(keyMAC, msg, SHA256).digest()
#Function to Generate MAC using MAC key + msg
def verify_mac(keyMAC, msg, macSent):
    return hmac.compare_digest(gen_mac(keyMAC, msg), macSent)

# Generate a master key
def generate_key():
    return get_random_bytes(16)  # AES-128 key size

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

kdc_private_key, kdc_public_key = generate_rsa_keys()
rsa_public_key_b = RSA.importKey(kdc_public_key)
rsa_private_key_b = RSA.importKey(kdc_private_key)
# Store client connections to forward messages
client_connections = []
clients = []
ID_bank = "Astartes"

def client_handler(connection, address):
    print(f"Connection from {address} has been established")
    client_connections.append(connection)

    try:
        while True:
            # Initial key distribution of public keys of server and client

            connection.send(rsa_public_key_b.exportKey())
            cliA_public_key = connection.recv(1024)
            rsa_public_key_a = RSA.import_key(cliA_public_key)
            encryptor = PKCS1_OAEP.new(rsa_public_key_a)
            decryptor = PKCS1_OAEP.new(rsa_private_key_b)
            
            # 1) Receive client info
            recv_cli_user = connection.recv(1024)
            cli_user = recv_cli_user.decode("UTF-8")
            print(f"Received client user: {cli_user}")
            connection.send("ACK".encode("UTF-8"))

            recv_cli_pass = connection.recv(1024)
            cli_pass = recv_cli_pass.decode("UTF-8")
            print(f"Received client password: {cli_pass}")

            new_client = Client(cli_user, cli_pass)
            clients.append(new_client)
            print(f"Created a new client: {new_client}")
            print("List of clients: ")
            for client in clients:
                print(client.username)

            # 2) Send Nk1 and IDk encrypted with PUa
            nonce1 = generate_nonce()
            message1 = nonce1 + ID_bank
            encrypted_message1 = encryptor.encrypt(message1.encode("UTF-8"))
            connection.send(encrypted_message1)

            # 3) Receive Na (nonce2) and Nk1 (nonce1) encrypted with PUk
            encrypted_message2 = connection.recv(1024)
            message2 = decryptor.decrypt(encrypted_message2)
            nonce2 = message2.decode("UTF-8")[:8]
            print(f"Encrypted message2: {encrypted_message2}")
            print(f"Decrypted message2: {message2}")
            print(f"Nonce Na: {nonce2}")

            # 4) Send Nk1 encrypted with PUa
            encrypted_message3 = encryptor.encrypt(nonce1.encode("UTF-8"))
            connection.send(encrypted_message3)

            ack = connection.recv(1024).decode("UTF-8")
            if ack != "ACK":
                print("Error: No ACK receivedß")

            # 5) Send master key Ka encrypted with PUa
            master_key = generate_key()
            #master_key = "thisisakey"
            encrypted_master_key = encryptor.encrypt(master_key)
            connection.send(encrypted_master_key)
            print(f"Sent Master key: {master_key}")

            """
            KDF to turn Master Key into Two AES keys (DataEncryption Key and MAC key)
            Master Key acts as both the Password and the Salt
            Both Client and Server will generate the Same Symmetric Key
            (or at least they should)
            Use the gen_mac function to generate MAC
            Use the cipher to encrypt and decrypt messages
            """
            keys = PBKDF2(master_key, master_key, 32, count=1000000, hmac_hash_module=SHA256)
            keyDE = keys[:16]
            keyMAC = keys[16:]
            cipher = AES.new(keyDE, AES.MODE_EAX)
            
            
    except Exception as e:
        print(f"Error with {address}: {e}")
    finally:
        connection.close()
        client_connections.remove(connection)

def start_server(host = localhost, port = portNum):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"Server listening on port: {port}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target = client_handler, args=(conn, addr))
            thread.start()
            print(f"Active connections: {len(client_connections)+1}")
    except KeyboardInterrupt:
        print("Server shutting down")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()