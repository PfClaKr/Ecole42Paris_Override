def decode_str(hex):
	try:
		full_decode = ""
		for part_encoded in hex:
			decode = bytes.fromhex(part_encoded).decode("utf-8")
			print(part_encoded, " | ", decode, " | ", decode[::-1])
			full_decode = full_decode + str(decode[::-1]) + " "
	except:
		print("Error: cannot decode HEX string to UTF-8")
		return ""
	return full_decode

if __name__ == "__main__":
	print("From HEX to UTF-8")
	input_hex = input("Encoded (hex) string: ")
	decode = decode_str(input_hex.split(" "))
	print("result: ", decode)
