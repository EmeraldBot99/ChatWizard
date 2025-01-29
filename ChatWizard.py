from google.cloud import firestore
from google.oauth2 import service_account
import json
from pathlib import Path
import os
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.ecc.curve import Curve
from axolotl.ecc.djbec import DjbECPublicKey
from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.util.keyhelper import KeyHelper
from axolotl.sessionbuilder import SessionBuilder
from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.sessioncipher import SessionCipher
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.invalidmessageexception import InvalidMessageException
import base64

APP_DIR = Path().home() / ".ChatWizard"
CONFIG_FILE = APP_DIR / "config.json"
APP_DIR.mkdir(parents=True, exist_ok=True)

class CryptoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, IdentityKeyPair):
            return {
                "type": "IdentityKeyPair",
                "publicKey": base64.b64encode(obj.getPublicKey().serialize()).decode('utf-8'),
                "privateKey": base64.b64encode(obj.getPrivateKey().serialize()).decode('utf-8')
            }
        elif isinstance(obj, SignedPreKeyRecord):
            return {
                "type": "SignedPreKeyRecord",
                "id": obj.getId(),
                "timestamp": obj.getTimestamp(),
                "keyPair": {
                    "publicKey": base64.b64encode(obj.getKeyPair().getPublicKey().serialize()).decode('utf-8'),
                    "privateKey": base64.b64encode(obj.getKeyPair().getPrivateKey().serialize()).decode('utf-8')
                },
                "signature": base64.b64encode(obj.getSignature()).decode('utf-8')
            }
        elif isinstance(obj, PreKeyRecord):
            return {
                "type": "PreKeyRecord",
                "id": obj.getId(),
                "keyPair": {
                    "publicKey": base64.b64encode(obj.getKeyPair().getPublicKey().serialize()).decode('utf-8'),
                    "privateKey": base64.b64encode(obj.getKeyPair().getPrivateKey().serialize()).decode('utf-8')
                }
            }
        return super().default(obj)

def decode_crypto_object(obj):
    if not isinstance(obj, dict):
        return obj
    
    obj_type = obj.get('type')
    if obj_type == 'IdentityKeyPair':
        public_key = Curve.decodePoint(
            base64.b64decode(obj['publicKey']),
            0
        )
        private_key = Curve.decodePrivatePoint(
            base64.b64decode(obj['privateKey'])
        )
        return IdentityKeyPair(public_key, private_key)
    elif obj_type == 'SignedPreKeyRecord':
        key_pair = Curve.generateKeyPair()
        key_pair._publicKey = Curve.decodePoint(
            base64.b64decode(obj['keyPair']['publicKey']),
            0
        )
        key_pair._privateKey = Curve.decodePrivatePoint(
            base64.b64decode(obj['keyPair']['privateKey'])
        )
        return SignedPreKeyRecord(
            obj['id'],
            obj['timestamp'],
            key_pair,
            base64.b64decode(obj['signature'])
        )
    elif obj_type == 'PreKeyRecord':
        key_pair = Curve.generateKeyPair()
        key_pair._publicKey = Curve.decodePoint(
            base64.b64decode(obj['keyPair']['publicKey']),
            0
        )
        key_pair._privateKey = Curve.decodePrivatePoint(
            base64.b64decode(obj['keyPair']['privateKey'])
        )
        return PreKeyRecord(obj['id'], key_pair)
    return obj

def generate_default_config():
    key_pair = Curve.generateKeyPair()
    identity_key_pair = IdentityKeyPair(key_pair.getPublicKey(), key_pair.getPrivateKey())
    registration_id = KeyHelper.generateRegistrationId()
    device_id = 1
    
    return {
        "username": None,
        "identity_key_pair": identity_key_pair,
        "registration_id": registration_id,
        "device_id": device_id,
        "theme": "dark",
        "signed_prekey": None,
        "preferences": {
            "notifications": True,
            "language": "en"
        }
    }

def load_or_create_config():
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("r") as f:
                config = json.loads(f.read(), object_hook=decode_crypto_object)
        else:
            raise FileNotFoundError
    except (json.JSONDecodeError, FileNotFoundError):
        print("Config file missing or invalid. Creating a new one...")
        config = generate_default_config()
    
    # Ensure all default values are present
    default_config = generate_default_config()
    for key, value in default_config.items():
        if key not in config:
            config[key] = value
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if sub_key not in config[key]:
                    config[key][sub_key] = sub_value
    
    # Prompt for username if missing
    if not config["username"]:
        config["username"] = input("Please enter your username: ").strip()
    
    # Save updated config
    with CONFIG_FILE.open("w") as f:
        json.dump(config, f, cls=CryptoJSONEncoder, indent=4)
    
    return config

def generate_signed_prekey(config):
    signed_prekey_id = 1
    signed_prekey = KeyHelper.generateSignedPreKey(
        config["identity_key_pair"],
        signed_prekey_id
    )
    config["signed_prekey"] = signed_prekey
    return config

    
def save_prekeys_to_firestore(config, service_account_key_path):
    # Generate one-time prekeys if they don't exist
    if not config.get("one_time_prekeys"):
        one_time_prekey_count = 100
        config["one_time_prekeys"] = KeyHelper.generatePreKeys(0, one_time_prekey_count)

    # Authenticate with Firebase
    credentials = service_account.Credentials.from_service_account_file(service_account_key_path)
    db = firestore.Client(credentials=credentials)

    # Prepare the user's data collection
    user_ref = db.collection('users').document(config['username'])
    
    # Prepare identity key data
    identity_key_data = {
        "registrationId": config["registration_id"],
        "deviceId": config["device_id"],
        "identityKey": base64.b64encode(
            config["identity_key_pair"].getPublicKey().serialize()
        ).decode('utf-8')
    }

    # Prepare signed prekey data
    signed_prekey = config["signed_prekey"]
    signed_prekey_data = {
        "keyId": signed_prekey.getId(),
        "publicKey": base64.b64encode(
            signed_prekey.getKeyPair().getPublicKey().serialize()
        ).decode('utf-8'),
        "signature": base64.b64encode(signed_prekey.getSignature()).decode('utf-8')
    }

    # Prepare one-time prekeys data
    prekeys_data = []
    for prekey in config["one_time_prekeys"]:
        prekey_data = {
            "keyId": prekey.getId(),
            "publicKey": base64.b64encode(
                prekey.getKeyPair().getPublicKey().serialize()
            ).decode('utf-8')
        }
        prekeys_data.append(prekey_data)

    # Combine all data
    user_data = {
        "identity": identity_key_data,
        "signedPreKey": signed_prekey_data,
        "preKeys": prekeys_data,
        "lastSeen": firestore.SERVER_TIMESTAMP
    }

    # Save to Firestore
    user_ref.set(user_data)
    print(f"Successfully saved keys for user {config['username']}")

    return user_data

def establish_session(config, db, recipient_username):
    # Get recipient's key data from Firestore
    recipient_ref = db.collection('users').document(recipient_username)
    recipient_doc = recipient_ref.get()
    
    if not recipient_doc.exists:
        raise ValueError(f"User {recipient_username} not found")
    
    recipient_data = recipient_doc.to_dict()
    
    # Get identity key
    identity_key_bytes = base64.b64decode(recipient_data['identity']['identityKey'])
    identity_key = Curve.decodePoint(identity_key_bytes, 0)
    
    # Get signed prekey
    signed_prekey_public = Curve.decodePoint(
        base64.b64decode(recipient_data['signedPreKey']['publicKey']),
        0
    )
    
    # Get one unused prekey (we'll use the first available one)
    if not recipient_data['preKeys']:
        raise ValueError("No available prekeys")
    
    prekey = recipient_data['preKeys'][0]
    prekey_public = Curve.decodePoint(base64.b64decode(prekey['publicKey']), 0)
    
    # Create PreKeyBundle
    prekey_bundle = PreKeyBundle(
        recipient_data['identity']['registrationId'],
        recipient_data['identity']['deviceId'],
        prekey['keyId'],
        prekey_public,
        recipient_data['signedPreKey']['keyId'],
        signed_prekey_public,
        base64.b64decode(recipient_data['signedPreKey']['signature']),
        identity_key
    )
    
    # Create SessionBuilder
    session_builder = SessionBuilder(
        config['storage'],
        config['storage'],
        config['storage'],
        config['storage'],
        recipient_username,
        config['device_id']
    )
    
    # Process PreKeyBundle to establish session
    try:
        session_builder.processPreKeyBundle(prekey_bundle)
        
        # Create SessionCipher for encrypting/decrypting messages
        session_cipher = SessionCipher(
            config['storage'],
            config['storage'],
            config['storage'],
            config['storage'],
            recipient_username,
            config['device_id']
        )
        
        # Remove used prekey from recipient's available prekeys
        new_prekeys = [pk for pk in recipient_data['preKeys'] if pk['keyId'] != prekey['keyId']]
        recipient_ref.update({'preKeys': new_prekeys})
        
        print(f"Session established with {recipient_username}")
        return session_cipher, recipient_data
        
    except Exception as e:
        raise Exception(f"Failed to establish session: {str(e)}")
    

def send_message(db, sender_username, recipient_username, encrypted_message):
    try:
        # Create message document
        message_data = {
            "sender": sender_username,
            "recipient": recipient_username,
            "content": encrypted_message["content"],
            "type": encrypted_message["type"],
            "timestamp": firestore.SERVER_TIMESTAMP,
            "read": False
        }
        
        # Add to recipient's mailbox
        mailbox_ref = db.collection('mailboxes').document(recipient_username)
        messages_ref = mailbox_ref.collection('messages')
        
        # Add the message
        messages_ref.add(message_data)
        
        # Update mailbox metadata
        mailbox_ref.set({
            'last_updated': firestore.SERVER_TIMESTAMP,
            'unread_count': firestore.Increment(1)
        }, merge=True)
        
        print(f"Message sent to {recipient_username}'s mailbox")
        
    except Exception as e:
        raise Exception(f"Failed to send message to mailbox: {str(e)}")

def receive_message(session_cipher, encrypted_message):
    try:
        # Decode the base64 message
        decoded = base64.b64decode(encrypted_message['content'])
        
        # Decrypt based on message type
        if encrypted_message['type'] == "prekey":
            message = PreKeyWhisperMessage(serialized=decoded)
        else:
            message = WhisperMessage(serialized=decoded)
            
        # Decrypt the message
        decrypted = session_cipher.decryptMessage(message)
        return decrypted.decode()
        
    except InvalidMessageException:
        raise Exception("Invalid message")
    except Exception as e:
        raise Exception(f"Failed to decrypt message: {str(e)}")

def read_mailbox(db, username, session_cipher, limit=50, mark_as_read=True):
    try:
        # Get messages from mailbox
        mailbox_ref = db.collection('mailboxes').document(username)
        messages_ref = mailbox_ref.collection('messages')
        
        # Query unread messages first, then read messages, ordered by timestamp
        unread_query = messages_ref.where('read', '==', False).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
        messages = unread_query.stream()
        
        decrypted_messages = []
        batch = db.batch()
        unread_count = 0
        
        for message in messages:
            msg_data = message.to_dict()
            
            # Prepare encrypted message for decryption
            encrypted_message = {
                "type": msg_data["type"],
                "content": msg_data["content"]
            }
            
            try:
                # Decrypt message
                decrypted_content = receive_message(session_cipher, encrypted_message)
                
                # Add to results
                decrypted_messages.append({
                    "id": message.id,
                    "sender": msg_data["sender"],
                    "content": decrypted_content,
                    "timestamp": msg_data["timestamp"],
                    "read": msg_data["read"]
                })
                
                # Mark as read if requested
                if mark_as_read and not msg_data["read"]:
                    batch.update(message.reference, {"read": True})
                    unread_count += 1
                    
            except Exception as e:
                print(f"Failed to decrypt message {message.id}: {str(e)}")
                continue
        
        # Commit read status updates
        if mark_as_read and unread_count > 0:
            batch.update(mailbox_ref, {
                "unread_count": firestore.Increment(-unread_count)
            })
            batch.commit()
        
        return decrypted_messages
        
    except Exception as e:
        raise Exception(f"Failed to read mailbox: {str(e)}")

def delete_message(db, username, message_id):

    try:
        mailbox_ref = db.collection('mailboxes').document(username)
        message_ref = mailbox_ref.collection('messages').document(message_id)
        
        # Check if message exists and is unread
        message_data = message_ref.get()
        if message_data.exists and not message_data.get('read'):
            # Decrease unread count
            mailbox_ref.update({
                'unread_count': firestore.Increment(-1)
            })
            
        # Delete the message
        message_ref.delete()
        print(f"Message {message_id} deleted")
        
    except Exception as e:
        raise Exception(f"Failed to delete message: {str(e)}")

if __name__ == "__main__":
    config = load_or_create_config()
    service_account_key_path = 'FIREBASE_SERVICE_ACCOUNT_KEY.json'
    credentials = service_account.Credentials.from_service_account_file(service_account_key_path)
    db = firestore.Client(credentials=credentials)
    
    try:
        # Example: Send a message
        recipient = "alice"
        session_cipher, _ = establish_session(config, db, recipient)
        
        message = "Hello, this is a secure message!"
        encrypted = send_message(session_cipher, message)
        send_message(db, config['username'], recipient, encrypted)
        
        
        messages = read_mailbox(db, config['username'], session_cipher)
        for msg in messages:
            print(f"From: {msg['sender']}")
            print(f"Message: {msg['content']}")
            print(f"Time: {msg['timestamp']}")
            print("---")
            
    except Exception as e:
        print(f"Error: {e}")
    
    



# # Path to your service account key file
# service_account_key_path = 'FIREBASE_SERVICE_ACCOUNT_KEY.json'

# # # Authenticate with Firebase using the service account key
# credentials = service_account.Credentials.from_service_account_file(service_account_key_path)

# # # Initialize the Firestore client with the provided credentials
# db = firestore.Client(credentials=credentials)

# # Specify the collection and document
# collection_name = 'users'
# document_name = 'user1'

# # Data to post
# data = {
#     'name': 'John Doe',
#     'email': 'johndoe@example.com',
#     'age': 30
# }

# # Add or set the data in Firestore
# if document_name:
#     db.collection(collection_name).document(document_name).set(data)
# else:
#     db.collection(collection_name).add(data)

# print(f"Data added to Firestore in collection '{collection_name}'!")