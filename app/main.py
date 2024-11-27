from typing import List, Optional, TypedDict
from ecdsa import SigningKey, SECP256k1
import hashlib
import base58
import json
import copy

class UTXO(TypedDict):
    txid: str
    vout: int
    value: int
    address: Optional[str]
    scriptPubKey: Optional[str]

class TransactionInput(TypedDict):
    txid: str
    vout: int
    scriptSig: str
    sequence: int
    scriptPubKey: str

class TransactionOutput(TypedDict):
    address: str
    value: int

class Transaction(TypedDict):
    version: int
    inputs: List[TransactionInput]
    outputs: List[TransactionOutput]
    locktime: int

def create_transaction(
    utxos: List[UTXO],
    target_address: str,
    amount: int,
    private_key: str
) -> str:
    if not private_key:
        raise ValueError("Private key is missing")

    if not utxos or len(utxos) == 0:
        raise ValueError("No UTXOs provided")

    if not target_address:
        raise ValueError("Target address is missing")

    if not isinstance(amount, int) or amount <= 0:
        raise ValueError("Invalid amount")

    transaction: Transaction = {
        "version": 1,
        "inputs": [],
        "outputs": [],
        "locktime": 0
    }

    total_input_value = 0
    for utxo in utxos:
        # Calculate total input value
        total_input_value += utxo["value"]

        # Create input with empty scriptPubKey
        transaction["inputs"].append({
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptSig": "",
            "sequence": 0xffffffff,
            "scriptPubKey": "" # Added required field
        })

    # Check if we have enough funds
    fee = calculate_fee(transaction)
    if total_input_value < amount + fee:
        raise ValueError("Insufficient funds")

    # Add the target output
    transaction["outputs"].append({
        "address": target_address,
        "value": amount
    })

    # Add change output if necessary
    change = total_input_value - amount - fee
    if change > 0:
        transaction["outputs"].append({
            "address": derive_address_from_private_key(private_key),
            "value": change
        })

    # Sign each input
    signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    public_key = signing_key.get_verifying_key().to_string().hex()

    for i in range(len(transaction["inputs"])):
        signature = generate_signature(private_key, transaction, i)
        transaction["inputs"][i]["scriptSig"] = create_script_sig(signature, public_key)

    return serialize_transaction(transaction)

def generate_signature(
    private_key: str,
    transaction: Transaction,
    index: int
) -> str:
    signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    tx_copy = copy.deepcopy(transaction)

    for input_tx in tx_copy["inputs"]:
        input_tx["scriptSig"] = ""

    tx_copy["inputs"][index]["scriptSig"] = tx_copy["inputs"][index].get("scriptPubKey", "")
    serialized_tx = serialize_transaction(tx_copy)
    serialized_tx_with_type = serialized_tx + "01000000"
    tx_hash = double_sha256(bytes.fromhex(serialized_tx_with_type))
    signature = signing_key.sign_deterministic(tx_hash)
    der_signature = signature.hex()

    return der_signature + "01"

def derive_address_from_private_key(private_key: str) -> str:
    signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    public_key = signing_key.get_verifying_key().to_string().hex()
    pub_key_bytes = bytes.fromhex(public_key)
    sha256_hash = hashlib.sha256(pub_key_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

    network_byte = bytes([0x6f])
    payload = network_byte + ripemd160_hash
    checksum = double_sha256(payload)[:4]

    return base58.b58encode(payload + checksum).decode()

def serialize_transaction(transaction: Transaction) -> str:
    serialized = ""
    serialized += int_to_little_endian_hex(transaction["version"], 4)
    serialized += var_int_to_hex(len(transaction["inputs"]))

    for input_tx in transaction["inputs"]:
        serialized += reverse_hex(input_tx["txid"])
        serialized += int_to_little_endian_hex(input_tx["vout"], 4)

        script_sig_bytes = bytes.fromhex(input_tx["scriptSig"])
        serialized += var_int_to_hex(len(script_sig_bytes))
        serialized += input_tx["scriptSig"]

        serialized += int_to_little_endian_hex(input_tx["sequence"], 4)

    serialized += var_int_to_hex(len(transaction["outputs"]))

    for output in transaction["outputs"]:
        serialized += int_to_little_endian_hex(output["value"], 8)

        script_pub_key = create_script_pub_key(output["address"])
        script_pub_key_bytes = bytes.fromhex(script_pub_key)
        serialized += var_int_to_hex(len(script_pub_key_bytes))
        serialized += script_pub_key

    serialized += int_to_little_endian_hex(transaction["locktime"], 4)
    return serialized

def create_script_pub_key(address: str) -> str:
    decoded = base58.b58decode(address)
    pub_key_hash = decoded[1:-4]
    script = bytes.fromhex("76a914") + pub_key_hash + bytes.fromhex("88ac")
    return script.hex()

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def int_to_little_endian_hex(number: int, bytes_length: int) -> str:
    hex_str = format(number, f'0{bytes_length * 2}x')
    return reverse_hex(hex_str)

def var_int_to_hex(number: int) -> str:
    if number < 0xfd:
        return format(number, '02x')
    elif number <= 0xffff:
        return "fd" + int_to_little_endian_hex(number, 2)
    elif number <= 0xffffffff:
        return "fe" + int_to_little_endian_hex(number, 4)
    else:
        return "ff" + int_to_little_endian_hex(number, 8)

def reverse_hex(hex_str: str) -> str:
    return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

def calculate_fee(transaction: Transaction) -> int:
    return 1000

def create_script_sig(signature: str, public_key: str) -> str:
    signature_bytes = bytes.fromhex(signature)
    public_key_bytes = bytes.fromhex(public_key)

    signature_length = len(signature_bytes)
    public_key_length = len(public_key_bytes)

    script_sig = (bytes([signature_length]) + signature_bytes +
                 bytes([public_key_length]) + public_key_bytes)

    return script_sig.hex()

__all__ = [
    'UTXO',
    'Transaction',
    'TransactionInput',
    'TransactionOutput',
    'create_script_pub_key',
    'generate_signature',
    'derive_address_from_private_key',
    'serialize_transaction',
    'double_sha256',
    'int_to_little_endian_hex',
    'var_int_to_hex',
    'reverse_hex',
    'calculate_fee',
    'create_script_sig',
]
