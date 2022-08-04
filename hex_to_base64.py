import base64
import string
import math
import enchant



def hex_to_bytes(input_hex: str) -> bytes:
    return bytes.fromhex(input_hex)


def print_as_base64(stuff: bytes):
    print(base64.b64encode(stuff))


def xor(hex_1: str, hex_2: str) -> hex:
    return int(hex_1, 16) ^ int(hex_2, 16)


def xor_bytes_to_char(our_bytes: bytes, other: chr) -> bytearray:
    return bytearray([(one_byte ^ ord(other)) for one_byte in our_bytes])


def xor_byte_to_char(our_byte: int, other: chr) -> int:
    return our_byte ^ ord(other)


def create_list_zeros(length_list: int) -> list:
    return [0] * length_list


def euclidian_distance(lttr_frqncy: list) -> float:
    sum_distance = 0
    for letter in range(len(lttr_frqncy)):
        standard_frequency_of_letter = LETTER_FREQUENCY_STANDARD[string.ascii_uppercase[letter]]
        sum_distance += (standard_frequency_of_letter - lttr_frqncy[letter]) ** 2 / standard_frequency_of_letter

    return math.sqrt(sum_distance)


def calculate_letter_frequency(decoded_bytes: bytes) -> list:
    letter_frequency = create_list_zeros(LETTERS_IN_ALPHABET)
    for j in range(LETTERS_IN_ALPHABET):
        letter_frequency[j] = decoded_bytes.count(bytes(chr(65 + j), 'ASCII'))
        letter_frequency[j] += decoded_bytes.count(bytes(chr(97 + j), 'ASCII'))

    sum_letters = sum(letter_frequency)
    if sum_letters != 0:
        letter_frequency = [absolute / sum_letters * 100 for absolute in letter_frequency]

    return letter_frequency


def get_euclidian_distance_for_multiple_keys(encoded_string_hex: string, number_of_keys: int = 128):
    euclidian_distances = [{} for _ in range(number_of_keys)]

    for single_char_key in range(0, number_of_keys):
        decrypted_bytes_array = xor_bytes_to_char(hex_to_bytes(encoded_string_hex), chr(single_char_key))
        euclidian_distances[single_char_key]["decrypted"] = decrypted_bytes_array
        euclidian_distances[single_char_key]["distance"] = euclidian_distance(calculate_letter_frequency(decrypted_bytes_array))
        euclidian_distances[single_char_key]["encrypted"] = encoded_string_hex
        euclidian_distances[single_char_key]["key"] = single_char_key

    return euclidian_distances


def xor_against_all_chars(encrypted: bytes) -> list[str]:
    return [(xor_bytes_to_char(encrypted, chr(i))).decode('ascii') for i in range(0, 128)]


def has_word(chars, d) -> bool:
    split_to_words = str(chars).split(" ")
    try:
        return any((d.check(seq) for seq in split_to_words))
    except:
        return False


def encrypt_string_repeated_xor(plaintext: string, key: string) -> string:
    bytes_plain = plaintext.encode('utf-8')

    list_integers = []
    for i, b in enumerate(bytes_plain):
        print("{:08b}".format(b))
        print("{:08b}".format(xor_byte_to_char(b, key[i % len(key)])))
        print("{:08b}".format(ord(key[i % len(key)])))
        print(key[i % len(key)])
        list_integers.append(xor_byte_to_char(b, key[i % len(key)]))

    return ''.join(format(x, '02x') for x in list_integers)


if __name__ == '__main__':
    s1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print_as_base64(hex_to_bytes(s1))
    s21 = '1c0111001f010100061a024b53535009181c'
    s22 = '686974207468652062756c6c277320657965'
    print("{:x}".format(xor(s21, s22)))
    s3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    s5 = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    key5 = "ICE"

    LETTER_FREQUENCY_STANDARD = {
        'A': 8.55, 'K': 0.81, 'U': 2.68, 'B': 1.60,
        'L': 4.21, 'V': 1.06, 'C': 3.16, 'M': 2.53,
        'W': 1.83, 'D': 3.87, 'N': 7.17, 'X': 0.19,
        'E': 12.1, 'O': 7.47, 'Y': 1.72, 'F': 2.18,
        'P': 2.07, 'Z': 0.11, 'G': 2.09, 'Q': 0.10,
        'H': 4.96, 'R': 6.33, 'I': 7.33, 'S': 6.73,
        'J': 0.22, 'T': 8.94
    }

    LETTERS_IN_ALPHABET = 26
"""
    get_euclidian_distance_for_multiple_keys(s3)
    possible_solutions = xor_against_all_chars(hex_to_bytes(s3))
    encryptedFile = r"encrypted.txt"
    decryptedFile = r"decrypted.txt"
    with open(encryptedFile, "r") as f:
        encryptedLines = f.read().splitlines()
    decryptions = []
    for line in encryptedLines:
        decryptions += get_euclidian_distance_for_multiple_keys(line)
    good_guesses = [guess for guess in decryptions if guess["distance"] < 15]
    with open(decryptedFile, "w") as f:
        d = enchant.Dict("en_US")
        for guess in good_guesses:
            if has_word(guess, d):
                f.write(str(guess) + "\n")
"""
print(encrypt_string_repeated_xor(s5, key5))
