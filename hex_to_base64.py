import binascii


def hex_to_base64(input_hex: str) -> bytes:
    # input_hex : input string in hex
    # output_base64 : string in base64
    raw_byte = binascii.unhexlify(input_hex)
    output_base64 = binascii.b2a_base64(raw_byte)

    return output_base64


if __name__ == '__main__':
    abc = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print(hex_to_base64(abc))
