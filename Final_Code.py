# Krish Vig and David Adetuwo

from flask import Flask, render_template, request, redirect, url_for, jsonify
import hashlib
import json
from time import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()


def hash_transaction(transaction):
    transaction_string = json.dumps(transaction, sort_keys=True).encode()
    return hashlib.sha256(transaction_string).hexdigest()


def sign_transaction(transaction, private_key):
    transaction_hash = hash_transaction(transaction)
    signature = private_key.sign(
        transaction_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(transaction, signature, public_key):
    transaction_hash = hash_transaction(transaction)
    try:
        public_key.verify(
            signature,
            transaction_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# Blockchain class
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, property_id, price, signature):
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'property_id': property_id,
            'price': price,
        }
        # Verify the transaction signature
        if verify_signature(transaction, signature, public_key):
            self.current_transactions.append(transaction)
            return self.last_block['index'] + 1
        else:
            return None

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while Blockchain.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


app = Flask(__name__)
blockchain = Blockchain()


@app.route('/')
def interface():
    message = request.args.get('message', '')  # Get the success message if it exists
    return render_template('interface.html', message=message)


@app.route('/submit_deal', methods=['POST'])
def submit_deal():
    price = request.form.get('price')
    address = request.form.get('address')
    if not price or not address:
        return "Missing price or address", 400
    transaction = {'sender': '0', 'recipient': 'user', 'property_id': address, 'price': price}
    signature = sign_transaction(transaction, private_key)
    transaction_index = blockchain.new_transaction('0', 'user', address, price, signature)
    if transaction_index:
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block['proof'])
        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)
        return redirect(url_for('interface', message='Successfully submitted and mined!'))
    else:
        return "Invalid transaction", 400


@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block['proof'])
    blockchain.new_transaction(
        sender="0",
        recipient="miner_address",
        property_id=None,
        price=0,
        signature=b''  # No signature needed for mining reward
    )
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/fullblockchain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


if __name__ == '__main__':
    app.run(debug=True)
