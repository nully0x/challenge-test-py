from typing import List, Dict, Optional, TypedDict
from ecdsa import SigningKey, SECP256k1
import hashlib
import base58

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
    scriptPubKey: Optional[str]

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

    if not utxos:
        raise ValueError("No UTXOs provided")

    if not target_address:
        raise ValueError("Target address is missing")

    if not isinstance(amount, int) or amount <= 0:
        raise ValueError("Invalid amount")

    total_input_value = sum(utxo["value"] for utxo in utxos)

    transaction: Transaction = {
        "version": 1,
        "inputs": [],
        "outputs": [],
        "locktime": 0
    }

    fee = calculate_fee(transaction)
    if total_input_value < amount + fee:
        raise ValueError("Insufficient funds")

    for utxo in utxos:
        script_pub_key = ""
        if utxo.get("address"):
            script_pub_key = create_script_pub_key(utxo["address"])

        transaction["inputs"].append({
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptSig": "",
            "sequence": 0xffffffff,
            "scriptPubKey": script_pub_key
        })

    transaction["outputs"].append({
        "address": target_address,
        "value": amount
    })

    change = total_input_value - amount - fee
    if change > 0:
        change_address = derive_address_from_private_key(private_key)
        transaction["outputs"].append({
            "address": change_address,
            "value": change
        })

    try:
        signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        public_key = signing_key.get_verifying_key().to_string().hex()

        for i in range(len(transaction["inputs"])):
            signature = generate_signature(private_key, transaction, i)
            transaction["inputs"][i]["scriptSig"] = create_script_sig(signature, public_key)
            del transaction["inputs"][i]["scriptPubKey"]

        return serialize_transaction(transaction)
    except Exception as e:
        raise ValueError(f"Transaction signing failed: {str(e)}")

def generate_signature(
    private_key: str,
    transaction: Transaction,
    index: int
) -> str:
    signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
    tx_copy = transaction.copy()

    for input_tx in tx_copy["inputs"]:
        input_tx["scriptSig"] = ""

    tx_copy["inputs"][index]["scriptSig"] = tx_copy["inputs"][index].get("scriptPubKey", "")
    serialized_tx = serialize_transaction(tx_copy)
    serialized_tx_with_type = serialized_tx + "01000000"
    tx_hash = double_sha256(bytes.fromhex(serialized_tx_with_type))
    signature = signing_key.sign_deterministic(tx_hash)

    return signature.hex() + "01"

def derive_address_from_private_key(private_key: str) -> str:
    try:
        private_key_bytes = bytes.fromhex(private_key)
        signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        public_key_bytes = verifying_key.to_string("compressed")

        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

        version_byte = bytes([0x6f])
        payload = version_byte + ripemd160_hash
        checksum = double_sha256(payload)[:4]
        final_bytes = payload + checksum

        return base58.b58encode(final_bytes).decode('utf-8')

    except ValueError as e:
        raise ValueError(f"Invalid private key format: {str(e)}")

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
    'create_script_sig'
]
