import hashlib

def hash_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def calculate_padding(data: bytes) -> bytes:
    """
    Computes the padding for a data as per the SHA-256 standard.

    Args:
        data (bytes): Input data as a byte string.

    Returns:
        bytes: The padded data.
    """
    # Get the original length of the data in bits
    original_bit_length = len(data) * 8

    # Step 1: Append a single '1' bit (0x80 in hex, as a byte)
    padding = b'\x80'

    # Step 2: Calculate the required padding length
    # Total data length (including original and padding) must be congruent to 448 mod 512
    # i.e., (original_length + padding_length + 64) % 512 == 0
    # where 64 is for the length field at the end
    total_length = original_bit_length + 8  # +8 for the '1' bit
    padding_length = (448 - (total_length % 512)) % 512
    padding_bytes = (padding_length // 8)  # Convert bits to bytes

    # Step 3: Append zero bytes to fill up to the calculated padding length
    padding += b'\x00' * padding_bytes

    # Step 4: Append the original data length as a 64-bit big-endian integer
    length_field = original_bit_length.to_bytes(8, byteorder='big')

    # Return the final padded data
    return padding + length_field

def calculate_padded_data(data: bytes) -> bytes:
    return data + calculate_padding(data)

