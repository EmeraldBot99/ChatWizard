from nacl.public import PrivateKey, PublicKey
import nacl
from pathlib import Path
from firebase_admin import auth, credentials, initialize_app, firestore
import nacl.signing
import json
from signal_protocol import curve, identity_key, state, storage, session, session_cipher, address
import random
import time

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from firebase_admin import auth

APP_DIR = Path().home() / ".ChatWizard"
CONFIG_FILE = APP_DIR / "config.json"
APP_DIR.mkdir(parents=True, exist_ok=True)

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

def encrypt_message(store, recipient_user_id, plaintext):
    recipient_address = address.ProtocolAddress(recipient_user_id, 1)
    
    ciphertext = session_cipher.message_encrypt(store, recipient_address,plaintext.encode())
    return ciphertext


def decrypt_message(store, sender_user_id, ciphertext):
    sender_address = address.ProtocolAddress(sender_user_id, 1)
    
    plaintext = session_cipher.message_decrypt(store, sender_address,ciphertext)
    return plaintext.decode()



class ChatWizardApp(App):
    def build(self):
        sm = ScreenManager()

        register_screen = RegisterScreen(name="register")
        login_screen = LoginScreen(name="login")

        sm.add_widget(register_screen)
        sm.add_widget(login_screen)

        return sm

if __name__ == '__main__':
    ChatWizardApp().run()













# testing
import time

cred = credentials.Certificate("FIREBASE_SERVICE_ACCOUNT_KEY.json")
initialize_app(cred)
db = firestore.client()


alice_user_id = "alice"
alice_user_data = generate_user_data(alice_user_id)
store_server_data(alice_user_id, alice_user_data)
store_local_data(alice_user_data,"bob_local_data.json")



bob_user_id = "bob"
bob_user_data = generate_user_data(alice_user_id)
store_server_data(bob_user_id, bob_user_data)
store_local_data(bob_user_data,"alice_local_data.json")



establish_session(alice_user_data,bob_user_id)


plaintext = "Never gonna' give you up, Never gonna' let you down, never gonna' run around and desert you"
ciphertext = encrypt_message(alice_user_data,bob_user_id,plaintext)

print(f"ciphertext: {ciphertext}")




decrypted_message = decrypt_message(bob_user_data,alice_user_id,ciphertext)
print(f"decrypted message: {decrypted_message}")


