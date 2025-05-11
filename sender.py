import party
import threading
import random
import psuedo_LCG
import hmac
import hashlib


class Sender(party.Party):

    def __init__(self, host='localhost', port=party.SENDER_PORT):
        super().__init__(host, port)
        self.socket.bind((host, port))
        self.socket.listen(5)

    def handle_client(self, client_socket, addr):
        receiver_thread = threading.Thread(
            target=self.receive_loop, args=(client_socket, addr))
        receiver_thread.start()

        sender_thread = threading.Thread(
            target=self.send_loop, args=(client_socket,))
        sender_thread.start()

    def send_loop(self, client_socket):
        while not self.lcg or not self.lcg.HMAC_key or not self.seed:
            pass

        while True:
            try:
                message = input("Enter a message to send: ")
                if message.lower() == 'exit':
                    break

                self.send_message(message, client_socket)
            except Exception as e:
                print(f"Error in send_loop: {e}")
                break

    def receive_loop(self, client_socket, addr):
        while True:
            try:
                # Receive data from the client
                data = client_socket.recv(1024)
                if not data:
                    break
                data = data.decode('utf-8')

                print(f"Received: {data}")

                # Check the type of event and process accordingly
                if data.startswith('key'):
                    self.handle_event_key(data, addr, client_socket)

                if data.startswith('HMAC_key'):
                    self.handle_event_seed(data, addr, client_socket)
                else:
                    print("Unknown event type")
            except Exception as e:
                print(f"Error: {e}")
                break

        client_socket.close()

    def handle_event_key(self, data, addr, client_socket):
        # Extract the data after 'event_key: '
        key_data = data[len('key: '):]
        print(f"Key data: {key_data}")

        self.encryption_algorithm.add_party(addr, int(key_data))

        # generate random key for HMAC

        self.generate_random_key()
        encrypted_random_key = self.encryption_algorithm.encrypt(
            self.lcg.HMAC_key, addr)
        self.send(client_socket, encrypted_random_key, "HMAC_key")

    def generate_hmac(self, data_bytes):

        return hmac.new(str(self.lcg.HMAC_key).encode('utf-8'), data_bytes, hashlib.sha256).hexdigest()

    def handle_event_seed(self, data, addr, client_socket):

        encrypted_seed = self.encryption_algorithm.encrypt(self.seed, addr)

        c1, c2 = encrypted_seed
        print("Encrypted Seed", c1, c2)
        seed_bytes = f"{c1},{c2}".encode('utf-8')

        seed_hmac = self.generate_hmac(seed_bytes)

        message = f"{c1},{c2}:{seed_hmac}"

        self.send(client_socket, message, "random_seed")

        # self.send(client_socket, self.encryption_algorithm.public_key, "key")

    def start_server(self):

        print(f"Server listening on port {party.SENDER_PORT}...")

        while True:
            # Accept incoming connections
            self.client_socket, addr = self.socket.accept()
            print(f"Connection established with {addr}")

            # Start a new thread to handle the client
            client_thread = threading.Thread(
                target=self.handle_client, args=(self.client_socket, addr))
            client_thread.start()

    def generate_random_key(self):
        # safely large random seed to protect from brute force attacks
        key = random.randint(2**20, 2**22)
        self.generate_random_seed()
        self.lcg = psuedo_LCG.LCG(seed=self.seed, HMAC_key=key)

    def generate_random_seed(self):
        # safely large random seed to protect from brute force attacks
        self.seed = random.randint(2**20, 2**22)

    def send(self, receiver_socket, data, data_name):
        # Send the data to the receiver
        receiver_socket.sendall(f"{data_name}: {data}".encode('utf-8'))

    def send_message(self, message, client_socket):

        message_bytes = message.encode('utf-8')

        next_key = self.lcg.keystream(len(message_bytes))

        message_encoded = [m ^ k for m, k in zip(message_bytes, next_key)]

        message_encoded = ",".join(map(str, message_encoded))

        self.send(client_socket, message_encoded, "message")
