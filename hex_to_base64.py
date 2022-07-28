import base64
import enchant


def hex_to_bytes(input_hex: str) -> bytes:
    return bytes.fromhex(input_hex)


def print_as_base64(stuff: bytes):
    print(base64.b64encode(stuff))


def xor(hex_1: str, hex_2: str) -> hex:
    return int(hex_1, 16) ^ int(hex_2, 16)


def xor_bytes_to_char(our_bytes: bytes, other: chr) -> bytearray:
    return bytearray([(one_byte ^ ord(other)) for one_byte in our_bytes])


def xor_against_all_chars(encrypted: bytes) -> list[str]:
    return [(xor_bytes_to_char(encrypted, chr(i))).decode('ascii') for i in range(0, 127)]


def check_for_words(candidates: list[str]):
    return [c for c in candidates if has_word(c)]


def has_word(chars) -> bool:
    d = enchant.Dict("en_US")
    split_to_words = chars.split(" ")
    try:
        return any((d.check(seq) for seq in split_to_words))
    except:
        return False


if __name__ == '__main__':
    s1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print_as_base64(hex_to_bytes(s1))
    s21 = '1c0111001f010100061a024b53535009181c'
    s22 = '686974207468652062756c6c277320657965'
    print("{:x}".format(xor(s21, s22)))
    s3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    possible_solutions = xor_against_all_chars(hex_to_bytes(s3))
    for solution in check_for_words(possible_solutions):
        print(solution)
