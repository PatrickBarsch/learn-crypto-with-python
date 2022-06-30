import base64


def hex_to_bytes(input_hex: str) -> bytes:
    return bytes.fromhex(input_hex)


def print_as_base64(stuff: bytes):
    print(base64.b64encode(stuff))


def xor(hex_1: str, hex_2: str) -> hex:
    return int(hex_1, 16) ^ int(hex_2, 16)


def xor_bytes_against_single_char(our_bytes: bytes, single_char: str) -> bytearray:
    return bytearray([(one_byte ^ ord(single_char)) for one_byte in our_bytes])


if __name__ == '__main__':
    s1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print_as_base64(hex_to_bytes(s1))
    s21 = '1c0111001f010100061a024b53535009181c'
    s22 = '686974207468652062756c6c277320657965'
    print("{:x}".format(xor(s21, s22)))
    s3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    for i in range(0,255):
        print_as_base64(xor_bytes_against_single_char(hex_to_bytes(s3), chr(i)))