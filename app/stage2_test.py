import pytest
from main import (
    create_transaction,
    UTXO,
    Transaction,
    TransactionInput,
    TransactionOutput
)

# Test fixtures
@pytest.fixture
def valid_utxo():
    return {
        "txid": "7ea75da574ebff364f0f4cc9d0315b7d9523f7f38558918aff8570842cba74c9",
        "vout": 0,
        "value": 50000
    }

@pytest.fixture
def valid_private_key():
    return "a1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

@pytest.fixture
def valid_target_address():
    return "2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF"

# Tests
def test_creates_valid_transaction_with_sufficient_funds(
    valid_utxo, valid_target_address, valid_private_key
):
    utxos = [valid_utxo]
    amount = 30000

    result = create_transaction(utxos, valid_target_address, amount, valid_private_key)
    assert result is not None
    assert isinstance(result, str)
    assert all(c in '0123456789abcdef' for c in result.lower())
    assert len(result) > 0

def test_throws_error_with_insufficient_funds(
    valid_target_address, valid_private_key
):
    utxos = [{
        "txid": "7ea75da574ebff364f0f4cc9d0315b7d9523f7f38558918aff8570842cba74c9",
        "vout": 0,
        "value": 500
    }]
    amount = 1000

    with pytest.raises(ValueError, match="Insufficient funds"):
        create_transaction(utxos, valid_target_address, amount, valid_private_key)

def test_validates_all_required_parameters(
    valid_utxo, valid_target_address, valid_private_key
):
    utxos = [valid_utxo]
    amount = 30000

    # Test missing private key
    with pytest.raises(ValueError, match="Private key is missing"):
        create_transaction(utxos, valid_target_address, amount, "")

    # Test missing UTXOs
    with pytest.raises(ValueError, match="No UTXOs provided"):
        create_transaction([], valid_target_address, amount, valid_private_key)

    # Test missing target address
    with pytest.raises(ValueError, match="Target address is missing"):
        create_transaction(utxos, "", amount, valid_private_key)

    # Test invalid amount
    with pytest.raises(ValueError, match="Invalid amount"):
        create_transaction(utxos, valid_target_address, 0, valid_private_key)

    with pytest.raises(ValueError, match="Invalid amount"):
        create_transaction(utxos, valid_target_address, -1000, valid_private_key)

def test_handles_multiple_utxos_correctly(
    valid_target_address, valid_private_key
):
    utxos = [
        {
            "txid": "7ea75da574ebff364f0f4cc9d0315b7d9523f7f38558918aff8570842cba74c9",
            "vout": 0,
            "value": 30000
        },
        {
            "txid": "8ea75da574ebff364f0f4cc9d0315b7d9523f7f38558918aff8570842cba74c9",
            "vout": 1,
            "value": 20000
        }
    ]
    amount = 45000

    result = create_transaction(utxos, valid_target_address, amount, valid_private_key)
    assert result is not None
    assert isinstance(result, str)
    assert all(c in '0123456789abcdef' for c in result.lower())

def test_creates_correct_change_output(
    valid_utxo, valid_target_address, valid_private_key
):
    utxos = [valid_utxo]
    amount = 30000

    result = create_transaction(utxos, valid_target_address, amount, valid_private_key)
    assert result is not None
    assert len(result) > 200  # Approximate length check

def test_creates_transaction_with_correct_format(
    valid_utxo, valid_target_address, valid_private_key
):
    utxos = [valid_utxo]
    amount = 30000

    result = create_transaction(utxos, valid_target_address, amount, valid_private_key)

    # Version should be first 8 characters (4 bytes)
    assert result[:8] == "01000000"

    # Transaction should end with locktime (4 bytes)
    assert result[-8:] == "00000000"

def test_handles_invalid_utxo_format(valid_target_address, valid_private_key):
    invalid_utxos = [{
        "vout": 0,
        "value": 50000
    }]  # Missing txid
    amount = 30000

    with pytest.raises(Exception):
        create_transaction(invalid_utxos, valid_target_address, amount, valid_private_key)

if __name__ == "__main__":
    pytest.main([__file__])
