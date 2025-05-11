import socket
import sender as senderClass
import receiver as receiverClass
import config


def main():
    print("Welcome to the Crypto Project!")
    print("Are you a sender or a receiver?")
    print("1. Sender")
    print("2. Receiver")

    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == '1':
        start_sender()
    elif choice == '2':
        start_receiver()
    else:
        print("Invalid choice. Please restart the program and choose 1 or 2.")


def start_sender():
    print("Starting as sender...")
    sender = senderClass.Sender()
    sender.start_server()

    sender.send_message("Hello world")


def start_receiver():
    print("Starting as receiver...")
    port = config.SERVER_PORT

    receiver = receiverClass.Receiver("localhost", int(port))
    receiver.start_receiver()
    print("Receiver started. Waiting for messages...")
    if not receiver.lcg:
        raise SystemError("LCG should be initialized with seed")


if __name__ == "__main__":
    main()
