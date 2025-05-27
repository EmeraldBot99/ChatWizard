from nacl.public import PrivateKey, PublicKey
import nacl
from pathlib import Path
from firebase_admin import auth, credentials, initialize_app, firestore
import nacl.signing
import json

import sys
import threading


if getattr(sys, 'frozen', False):
    base_dir = Path(sys._MEIPASS)  
else:
    base_dir = Path(__file__).resolve().parent  


service_account_key_path = base_dir / "serviceAccountKey.json"


if getattr(sys, 'frozen', False):  
    base_dir = Path(sys._MEIPASS)  
else:
    base_dir = Path(__file__).resolve().parent 


# signal_protocol_path = base_dir / "signal-protocol"
# if signal_protocol_path.exists():
#     sys.path.insert(0, str(signal_protocol_path))
# else:
#     raise FileNotFoundError(f"signal-protocol folder not found at {signal_protocol_path}")

from signal_protocol import curve, identity_key, state, storage, session, session_cipher, address, protocol
import random
import time

from firebase_admin import auth

APP_DIR = Path().home() / ".ChatWizard"
CONFIG_FILE = APP_DIR / "config.json"
APP_DIR.mkdir(parents=True, exist_ok=True)
USERNAME = None
USER_STORE = None

# user handling
def register_user(email, password):
    user = auth.create_user(email=email, password=password)
    print("User created:", user.uid)



def generate_user_data(user):
    user_keypair = curve.KeyPair.generate()
    identity_keypair = identity_key.IdentityKeyPair.generate()
    registration_id = random.randint(0,10000000)
    store = storage.InMemSignalProtocolStore(identity_keypair, registration_id)
    #prekey data

    for i in range(99):
        pre_key_record = state.PreKeyRecord(i, curve.KeyPair.generate())
        store.save_pre_key(i, pre_key_record)

    #signed prekeys
    for i in range(100,110):
        signed_prekey_pair = curve.KeyPair.generate()
        serialized_signed_prekey_pub = signed_prekey_pair.public_key().serialize()
        signed_pre_key_signature = (store.get_identity_key_pair().private_key().calculate_signature(serialized_signed_prekey_pub))
        
        signed_prekey = state.SignedPreKeyRecord(
                i,
                round(time.time()), # This is a timestamp since this key should be periodically rotated
                signed_prekey_pair,
                signed_pre_key_signature,
            )
        # if(i == 100):
        #     print(dir(signed_prekey))
        store.save_signed_pre_key(i, signed_prekey)

    return store



#user data handling


def store_server_data(user_id, store):
    db = firestore.client()
    server_data = {
        "registration_id": store.get_local_registration_id(),
        "identity_public": store.get_identity_key_pair().public_key().serialize().hex(),
        "public_prekeys": [{"id": i, "public_key": store.get_pre_key(i).public_key().serialize().hex()} for i in range(0,99)],
        "signed_prekeys_public": [{"id": i, "public_key": store.get_signed_pre_key(i).public_key().serialize().hex(), "signature": store.get_signed_pre_key(i).signature().hex(),} for i in range(100,110)],

    }
    db.collection("users").document(user_id).set(server_data)
    print(f"server data stored at {user_id}")



#TODO make storing local data store in local secure storage
#TODO make password encrypted
def store_local_data(store,filename):
    user_local_data = {
        "registration_id": store.get_local_registration_id(),
        "identity_keypair": store.get_identity_key_pair().serialize().hex(),
        "prekeys":  [{"id": i, "keypair": store.get_pre_key(i).serialize().hex()} for i in range(0,99)],
        "signed_prekeys":  [{"id": i, "keypair": store.get_signed_pre_key(i).serialize().hex()} for i in range(100,110)],
        "sessions": {}
    }
        
    with open(APP_DIR / filename, "w") as f:
        json.dump(user_local_data, f)

    print("user local data stored.")


def create_in_mem_store(filename):
    
    with open(APP_DIR / filename, "r") as f:
        data = json.load(f)

    registration_id = data["registration_id"]
    identity_keypair = identity_key.IdentityKeyPair.from_bytes(bytes.fromhex(data["identity_keypair"]))
    store = storage.InMemSignalProtocolStore(identity_keypair, registration_id)

    for prekey in data["prekeys"]:
        keypair = state.PreKeyRecord.deserialize(bytes.fromhex(prekey["keypair"]))
        store.save_pre_key(prekey["id"],keypair)

    for signed_prekey in data["signed_prekeys"]:
        keypair = state.SignedPreKeyRecord.deserialize(bytes.fromhex(signed_prekey["keypair"]))
        store.save_signed_pre_key(signed_prekey["id"],keypair)

    return store
    
#TODO delete prekeys
def get_prekey_bundle(user_id):
    db = firestore.client()
    doc_ref = db.collection("users").document(user_id)
    user_data = doc_ref.get().to_dict()

    if not user_data:
        raise ValueError(f"no data found for user {user_id}")
    
    
    identity_key_public = identity_key.IdentityKey(
        bytes.fromhex(user_data["identity_public"])
    )

    
    selected_prekey = random.choice(user_data["public_prekeys"])
    pre_key_id = selected_prekey["id"]
    pre_key_public = curve.PublicKey.deserialize(bytes.fromhex(selected_prekey["public_key"]))

    signed_prekey = user_data["signed_prekeys_public"][-1]
    signed_pre_key_id = signed_prekey["id"]
    signed_pre_key_public = curve.PublicKey.deserialize(bytes.fromhex(signed_prekey["public_key"]))
    signed_pre_key_signature = bytes.fromhex(signed_prekey["signature"])

    recipient_bundle = state.PreKeyBundle(registration_id=user_data["registration_id"],device_id = 1, signed_pre_key_id = signed_pre_key_id, signed_pre_key_public = signed_pre_key_public, signed_pre_key_signature = signed_pre_key_signature, identity_key = identity_key_public)

    return recipient_bundle

def establish_session(store, user_id):
    recipient_address = address.ProtocolAddress(user_id, 1)
    recipient_bundle = get_prekey_bundle(user_id)
    session.process_prekey_bundle(recipient_address, store, recipient_bundle)

    print(f"Session established with {user_id}")
    return store

def store_session(store,recipient_id,filename):
    with open (APP_DIR / filename, "r") as f:
        data = json.load(f)

    data[recipient_id] = store.load_session(address.ProtocolAddress(recipient_id, 1)).serialize().hex()

    with open(APP_DIR / filename, "w" ) as f:
        json.dump(data,f)

    print("session stored")

def load_session(store, recipient_id, filename):
    with open (APP_DIR / filename, "r") as f:
        data = json.load(f)

    if recipient_id in data:
        store.store_session(address.ProtocolAddress(recipient_id, 1),state.SessionRecord.deserialize(bytes.fromhex(data[recipient_id]))) 

        print("session loaded")
        return store
    
    else:
        return False


def encrypt_message(store, recipient_user_id, plaintext):
    recipient_address = address.ProtocolAddress(recipient_user_id, 1)
    
    ciphertext = session_cipher.message_encrypt(store, recipient_address,plaintext.encode())
    return ciphertext


def decrypt_message(store, sender_user_id, ciphertext):
    sender_address = address.ProtocolAddress(sender_user_id, 1)
    
    plaintext = session_cipher.message_decrypt(store, sender_address,ciphertext)
    return plaintext.decode()


#TODO send notification when message sent
def send_message(store, recipient_user_id,sender_user_id, plaintext):
    new_message = encrypt_message(store,recipient_user_id,plaintext).serialize()

    db = firestore.client()

    mailbox_ref = db.collection("mailbox").document(recipient_user_id)
    mailbox_doc = mailbox_ref.get()

    if mailbox_doc.exists:
        mailbox_data = mailbox_doc.to_dict()
        if "messages" in mailbox_data:
            messages = mailbox_data["messages"]
        else:
            messages = []
    else:
        messages = []

    messages.append({"message": new_message, "sender_user_id": sender_user_id})

    mailbox_ref.set({"messages": messages})
    store_message_history(sender_user_id, recipient_user_id, plaintext, True)

def check_mailbox(store, recipient_user_id):
    # store = create_in_mem_store(f"tester.json")
    print(recipient_user_id)
    db = firestore.client()
    try:
        mailbox_ref = db.collection("mailbox").document(recipient_user_id)
        mailbox = mailbox_ref.get().to_dict()
        print("mailbox_______________________")

        decrypted = []
        if mailbox and "messages" in mailbox:
            for message in mailbox["messages"]:
                try:
                    decrypted_msg = decrypt_message(
                        store, 
                        message["sender_user_id"],
                        protocol.PreKeySignalMessage.try_from(message["message"])
                    )
                    timestamp = message.get("timestamp", int(time.time()))
                    decrypted.append([
                        decrypted_msg,
                        message["sender_user_id"],
                        timestamp
                    ])
                    
                    store_message_history(recipient_user_id, message["sender_user_id"], decrypted_msg, False)
                except Exception as e:
                    print(f"Error decrypting message: {e}")

            mailbox_ref.set({"messages": []})
        
        print(decrypted)
        return decrypted
    except (TypeError) as e:
        print(f"Error checking mailbox: {e}")
        return []
    
    
def store_message_history(user_id, contact_id, message, is_sent):
    history_dir = APP_DIR / "message_history"
    history_dir.mkdir(exist_ok=True)
    
    chat_id = f"{min(user_id, contact_id)}_{max(user_id, contact_id)}"
    history_file = history_dir / f"{chat_id}.json"
    
    if not history_file.exists():
        with open(history_file, "w") as f:
            json.dump([], f)
    
    with open(history_file, "r") as f:
        try:
            history = json.load(f)
        except json.JSONDecodeError:
            history = []
    
    history.append({
        "sender": user_id if is_sent else contact_id,
        "receiver": contact_id if is_sent else user_id,
        "message": message,
        "timestamp": int(time.time()),
        "is_sent": is_sent
    })
    
    with open(history_file, "w") as f:
        json.dump(history, f)

def get_message_history(user_id, contact_id):
    history_dir = APP_DIR / "message_history"
    chat_id = f"{min(user_id, contact_id)}_{max(user_id, contact_id)}"
    history_file = history_dir / f"{chat_id}.json"
    
    if not history_file.exists():
        return []
        
    with open(history_file, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []
        
def get_contacts(user_id):
    history_dir = APP_DIR / "message_history"
    history_dir.mkdir(exist_ok=True)
    
    contacts = set()
    for file in history_dir.glob("*.json"):
        parts = file.stem.split("_")
        if len(parts) == 2:
            if parts[0] == user_id:
                contacts.add(parts[1])
            elif parts[1] == user_id:
                contacts.add(parts[0])
    
    return list(contacts)

def get_all_users():
    db = firestore.client()
    users = db.collection("uselfsers").stream()
    return [user.id for user in users]

def read_messages(user_data,username):
    while True:
        messages = check_mailbox(user_data,username)
        # print("checking mailbox...")

        if (len(messages) > 0):
            for message in messages:
                print(f"{message[1]} says: {message[0]}")

        time.sleep(5)


# testing
import time
import keyboard
import sys
import threading



cred = credentials.Certificate(str(service_account_key_path))
initialize_app(cred)


db = firestore.client()


if len(sys.argv) == 2: 
    username = sys.argv[1]

else:
    
    username = "123"


if (APP_DIR / (f"{username}.json")).exists():
    user_data = create_in_mem_store(f"{username}.json")
else:
    user_data = generate_user_data(username)
    store_server_data(username, user_data)
    store_local_data(user_data, f"{username}.json")


#TODO create a simalar system to this where a thread is always running, reading messages.
#then when a message is recieved it updates the message history, which the app uses to display messages.
thread = threading.Thread(target=read_messages, args=(user_data, username), daemon=True)
thread.start()


while True:
    pass

# read_messages(user_data, username)


# while (True):
#     if keyboard.is_pressed("s"):
#         recipient_id = input("who would you like to send a message to? (enter nothing to cancel) ")
#         if (recipient_id != ""):
#             if (not load_session(user_data,recipient_id,f"{username}.json")):
#                 establish_session(user_data,recipient_id)
#                 store_session(user_data,recipient_id,f"{username}.json")
            
#             plaintext = input("whats the message? ")
#             if (plaintext != ""):
#                 send_message(user_data,recipient_id,username,plaintext)
#                 store_session(user_data,recipient_id,f"{username}.json")
#                 print("message sent")


