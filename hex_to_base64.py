import binascii


def hex_to_base64(input_hex: str) -> bytes:
    # input_hex : input string in hex
    # output_base64 : string in base64
    raw_byte = binascii.unhexlify(input_hex)
    output_base64 = binascii.b2a_base64(raw_byte)

    return output_base64


def fixed_xor(hex_1: str, hex_2: str) -> hex:
    raw_byte_1 = int(hex_1, 16)
    raw_byte_2 = int(hex_2, 16)

    result = raw_byte_1 ^ raw_byte_2

    return hex(result)


if __name__ == '__main__':
    abc = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print(hex_to_base64(abc))
    print(fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))


