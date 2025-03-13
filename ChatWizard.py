from nacl.public import PrivateKey, PublicKey
import nacl
from pathlib import Path
from firebase_admin import auth, credentials, initialize_app
import nacl.signing


APP_DIR = Path().home() / ".ChatWizard"
CONFIG_FILE = APP_DIR / "config.json"
APP_DIR.mkdir(parents=True, exist_ok=True)



# user handling
def register_user(email, password):
    user = auth.create_user(email=email, password=password)
    print("User created:", user.uid)



# cryptographic primatives
def generate_keypair():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

def generate_identity_key():
    identity_private = nacl.signing.SigningKey.generate()
    identity_public = identity_private.verify_key
    return identity_private, identity_public

def generate_one_time_prekeys(count=10):
    prekeys = []
    for _ in range(count):
        prekey_private = nacl.public.PrivateKey.generate()
        prekey_public = prekey_private.public_key
        prekeys.append((prekey_private, prekey_public))
    return prekeys

#user data handling
