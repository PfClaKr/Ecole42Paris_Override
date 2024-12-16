import binascii

def decode_str(hex_list):
	try:
		full_decode = ""
		for part_encoded in hex_list:
			decoded_bytes = binascii.unhexlify(part_encoded)
			decode = decoded_bytes.decode("utf-8")
			print("{} | {} | {}".format(part_encoded, decode, decode[::-1]))
			full_decode += decode[::-1] + " "
	except Exception as e:
		print("Error: cannot decode HEX string to UTF-8. {}".format(e))
		return ""
	return full_decode

if __name__ == "__main__":
	print("From HEX to UTF-8")
	input_hex = raw_input("Encoded (hex) string: ")
	hex_list = input_hex.split()
	decode = decode_str(hex_list)
	print("result: {}".format(decode))
