import os
from google.cloud import firestore

# Firebase credentials are set through the environment variable in GitHub Actions
db = firestore.Client()

# Specify the collection and document
collection_name = 'users'
document_name = 'user1'

# Data to post
data = {
    'name': 'John Doe',
    'email': 'johndoe@example.com',
    'age': 30
}

# Add or set the data in Firestore
if document_name:
    db.collection(collection_name).document(document_name).set(data)
else:
    db.collection(collection_name).add(data)

print(f"Data added to Firestore in collection '{collection_name}'!")
