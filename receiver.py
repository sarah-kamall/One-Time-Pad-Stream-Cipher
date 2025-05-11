import party
import psuedo_LCG
import hmac
import hashlib
import config


class Receiver(party.Party):

    def __init__(self, server_host, server_port, my_host='localhost', my_port=party.RECEIEVER_PORT):
        self.server_host = server_host
        self.server_port = server_port
        super().__init__(my_host, my_port)
        self.output_file = open(config.OUTPUT_FILE, "w")

    def handle_event_key(self, data):

        key_data = data[len('key: '):]
        addr = (self.server_host, self.server_port)
        self.encryption_algorithm.add_party(addr, key_data)

    def verify_hmac(self, data_bytes, received_hmac):
        computed_hmac = hmac.new(
            str(self.lcg.HMAC_key).encode('utf-8'), data_bytes,
            hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed_hmac, received_hmac)

    def handle_event_seed(self, data):

        seed_data = data[len('random_seed: '):]
        print(seed_data)

        encrypted_part, received_hmac = seed_data.split(":")
        c1_str, c2_str = encrypted_part.split(",")

        seed_bytes = encrypted_part.encode('utf-8')

        # Verify HMAC
        if not self.verify_hmac(seed_bytes, received_hmac):
            print("HMAC verification failed for seed! Tampered or invalid!")
            return

        c1, c2 = int(c1_str), int(c2_str)

        decrypted_seed = self.encryption_algorithm.decrypt(c1, c2)
        self.seed = decrypted_seed
        self.lcg.state = self.seed
        print("Receiver got seed:", decrypted_seed)

    def handle_event_Hmac_key(self, data):
        key_data = data[len('HMAC_key: '):]
        print(key_data)
        c1, c2 = tuple(map(int, key_data.strip("()").split(",")))
        decrypted_key = self.encryption_algorithm.decrypt(c1, c2)
        self.lcg = psuedo_LCG.LCG(seed=None, HMAC_key=decrypted_key)
        print("Reciever got key", decrypted_key)

    def start_receiver(self):

        self.socket.connect((self.server_host, self.server_port))

        self.send(self.encryption_algorithm.public_key, "key")

        while True:
            try:
                # Receive data from the client
                data = self.socket.recv(1024)
                if not data:
                    break
                data = data.decode('utf-8')

                print(f"Received: {data}")

                # Check the type of event and process accordingly
                if data.startswith('key'):
                    self.handle_event_key(data)

                elif data.startswith('HMAC_key'):
                    self.handle_event_Hmac_key(data)
                    self.send(0, "HMAC_key")  # ack

                elif data.startswith('random_seed'):
                    self.handle_event_seed(data)

                elif data.startswith('message'):
                    self.handle_event_message(data)
                else:
                    print("Unknown event type")

            except Exception as e:
                print(f"Error: {e}")

    def handle_event_message(self, data):

        message = data[len('message: '):]

        message_array = list(map(int, message.split(",")))

        next_key = self.lcg.keystream(len(message_array))

        decrypted_bytes = bytes(
            [m ^ k for m, k in zip(message_array, next_key)])
        print("Decrypted bytes:", decrypted_bytes)
        original_message = decrypted_bytes.decode('utf-8')

        print("Decrypted message:", original_message)

    def send(self, data, data_name):

        self.socket.sendall(f"{data_name}: {data}".encode('utf-8'))
