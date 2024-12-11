import sys

def little_endian_to_string(hex_chunks):
    """
    Converts hex chunks in little-endian format to an ASCII string.

    Args:
        hex_chunks (list of str): A list of hexadecimal strings.

    Returns:
        str: The decoded ASCII string.
    """
    result = ""

    for chunk in hex_chunks:
        # Reverse every 8-character group within the chunk (4 bytes per group)
        reversed_chunk = "".join(
            chunk[i:i+2] for i in range(0, len(chunk), 2)
        )[::-1]

        # Convert the reversed hex string to bytes
        try:
            bytes_data = bytes.fromhex(reversed_chunk)
            # Decode the bytes to ASCII and add to the result
            result += bytes_data.decode('ascii')
        except ValueError:
            # Handle cases where the hex cannot be converted or decoded
            result += "[INVALID HEX]"

    return result

if __name__ == "__main__":
    print("Enter hex strings separated by spaces:")
    input_hex = sys.stdin.read().strip()
    hex_chunks = input_hex.split()  # Split the input by spaces
    output_string = little_endian_to_string(hex_chunks)
    print(output_string)
