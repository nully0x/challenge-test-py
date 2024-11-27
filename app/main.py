from typing import List, Optional, TypedDict, Union
from ecdsa import SigningKey, SECP256k1
import hashlib
import base58

# Type definitions
class UTXO(TypedDict):
    txid: str
    vout: int
    value: int
    address: Optional[str]
    scriptPubKey: Optional[str]

class TransactionInput(TypedDict, total=False):
    txid: str
    vout: int
    scriptSig: str
    sequence: int
    scriptPubKey: Optional[str]

class TransactionOutput(TypedDict):
    address: str
    value: int
    scriptPubKey: str

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
    try:
        # Input validation
        if not private_key:
            raise Exception("Private key is missing")
        if not utxos or len(utxos) == 0:
            raise Exception("No UTXOs provided")
        if not target_address:
            raise Exception("Target address is missing")
        if not isinstance(amount, (int, float)) or amount <= 0:
            raise Exception("Invalid amount")

        # Step 1: Initialize a transaction object
        transaction: Transaction = {
            "version": 1,
            "inputs": [],
            "outputs": [],
            "locktime": 0
        }

        # Step 2: Add inputs (UTXOs)
        total_input_value = 0
        for utxo in utxos:
            if not utxo.get("scriptPubKey") and utxo.get("address"):
                address = utxo.get("address")
                if address is not None:
                    utxo["scriptPubKey"] = create_script_pub_key(address)

            transaction["inputs"].append({
                "txid": utxo["txid"],
                "vout": utxo["vout"],
                "scriptSig": "",
                "sequence": 0xffffffff,
                "scriptPubKey": utxo["scriptPubKey"]
            })
            total_input_value += utxo["value"]

        # Step 3: Calculate fee and verify funds
        fee = calculate_fee(transaction)
        if total_input_value < amount + fee:
            raise Exception("Insufficient funds")

        # Step 4: Add output (target address)
        script_pub_key = create_script_pub_key(target_address)
        transaction["outputs"].append({
            "address": target_address,
            "value": amount,
            "scriptPubKey": script_pub_key
        })

        # Step 5: Add change output if needed
        change_amount = total_input_value - amount - fee
        if change_amount > 0:
            change_address = derive_address_from_private_key(private_key)
            change_script_pub_key = create_script_pub_key(change_address)
            transaction["outputs"].append({
                "address": change_address,
                "value": change_amount,
                "scriptPubKey": change_script_pub_key
            })

        # Step 6: Sign each input
        signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        for i, input_tx in enumerate(transaction["inputs"]):
            signature = generate_signature(private_key, transaction, i)
            input_tx["scriptSig"] = signature
            if "scriptPubKey" in input_tx:
                del input_tx["scriptPubKey"]

        return serialize_transaction(transaction)

    except Exception as error:
        print(f"Error creating transaction: {error}")
        raise

def generate_signature(
    private_key: str,
    transaction: Transaction,
    index: int
) -> str:
    # Implementation details...
    return ""

def derive_address_from_private_key(private_key: str) -> str:
    # Implementation details...
    return ""

def serialize_transaction(transaction: Transaction) -> str:
    # Implementation details...
    return ""

def create_script_pub_key(address: str) -> str:
    # Implementation details...
    return ""

def double_sha256(buffer: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(buffer).digest()).digest()

def int_to_little_endian_hex(number: int, bytes_length: int) -> str:
    hex_str = format(number, f'0{bytes_length * 2}x')
    return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

def var_int_to_hex(number: int) -> str:
    # Implementation details...
    return ""

def reverse_hex(hex_str: str) -> str:
    if not hex_str:
        return ""
    hex_pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    return ''.join(reversed(hex_pairs))

def calculate_fee(transaction: Transaction) -> int:
    return 1000  # Fixed fee for now

def create_script_sig(signature: str, public_key: str) -> str:
    # Implementation details...
    return ""

__all__ = [
    'create_transaction',
    'generate_signature',
    'derive_address_from_private_key',
    'serialize_transaction',
    'create_script_pub_key',
    'double_sha256',
    'int_to_little_endian_hex',
    'var_int_to_hex',
    'reverse_hex',
    'calculate_fee',
    'create_script_sig',
    'UTXO',
    'Transaction',
    'TransactionInput',
    'TransactionOutput'
]
