def create_pattern(length):
    """
    지정된 길이만큼 고유한 테스트 문자열을 생성합니다.
    """
    pattern = ""
    for i in range(1, 27):  # a-z 반복
        for j in range(1, 27):  # a-z 반복
            for k in range(10):  # 0-9 반복
                if len(pattern) < length:
                    pattern += chr(96 + i) + chr(96 + j) + str(k)
    return pattern[:length]


def hex_to_little_endian_ascii(hex_value):
    """
    16진수를 리틀 엔디안으로 변환하고 ASCII 문자열로 변환합니다.
    """
    # 16진수 문자열을 바이트 배열로 분리
    hex_str = f"{hex_value:08x}"  # 8자리 16진수로 포맷
    bytes_list = [hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]
    
    # 리틀 엔디안 순서로 바이트 뒤집기
    little_endian_bytes = bytes_list[::-1]
    
    # ASCII 문자로 변환
    ascii_chars = ''.join(chr(int(byte, 16)) for byte in little_endian_bytes)
    return ascii_chars


def find_offset(value, length):
    """
    생성된 패턴에서 특정 값의 오프셋을 찾습니다.
    """
    pattern = create_pattern(length)
    offset = pattern.find(value)
    if offset == -1:
        return f"'{value}' not found in the pattern!"
    return f"'{value}' found at offset: {offset}"


if __name__ == "__main__":
    print("=== Buffer Overflow Pattern Generator & Offset Finder ===")
    
    # 패턴 생성
    try:
        length = int(input("Enter the length of the pattern to generate: "))
        pattern = create_pattern(length)
        print(f"Generated pattern ({length} bytes):")
        print(pattern)
    except ValueError:
        print("Invalid input! Please enter a numeric value for length.")
        exit(1)
    
    # 특정 값 입력 및 변환
    try:
        hex_value = int(input("\nEnter the hex value to find (e.g., 0x63613563): "), 16)
        search_value = hex_to_little_endian_ascii(hex_value)
        print(f"Little Endian ASCII representation: '{search_value}'")
    except ValueError:
        print("Invalid input! Please enter a valid hex value.")
        exit(1)
    
    # 특정 값 오프셋 찾기
    result = find_offset(search_value, length)
    print(result)
