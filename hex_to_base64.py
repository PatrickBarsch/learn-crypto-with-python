import base64
import string
import numpy as np


def hex_to_bytes(input_hex: str) -> bytes:
    return bytes.fromhex(input_hex)


def print_as_base64(stuff: bytes):
    print(base64.b64encode(stuff))


def xor(hex_1: str, hex_2: str) -> hex:
    return int(hex_1, 16) ^ int(hex_2, 16)


def xor_bytes_against_single_char(our_bytes: bytes, other: chr) -> bytearray:
    return bytearray([(one_byte ^ ord(other)) for one_byte in our_bytes])


def create_empty_list(length_list : int) -> list:
    return [0 for letter in range(length_list)]


def euclidian_distance(lttr_frqncy: list) -> float:
    sum_distance = 0
    for letter in range(len(lttr_frqncy)):
        standard_frequency_of_letter = LETTER_FREQUENCY_STANDARD[string.ascii_uppercase[letter]]
        sum_distance += (standard_frequency_of_letter - lttr_frqncy[letter]) ** 2 / standard_frequency_of_letter

    return np.sqrt(sum_distance)


def calculate_letter_frequency(decoded_bytes: bytes) -> list :
    letter_frequency = create_empty_list(LETTERS_IN_ALPHABET)
    for j in range(LETTERS_IN_ALPHABET):
        letter_frequency[j] = decoded_bytes.count(bytes(chr(65 + j), 'ASCII'))
        letter_frequency[j] += decoded_bytes.count(bytes(chr(97 + j), 'ASCII'))

    sum_letters = sum(letter_frequency)
    if sum_letters != 0:
        letter_frequency = [absolute / sum_letters * 100 for absolute in letter_frequency]

    return letter_frequency



def get_euclidian_distance_for_multiple_keys(encoded_string_hex : string, number_of_keys: int):
    euclidian_distance_key = [0 for single_char_key in range(number_of_keys)]

    for single_char_key in range(0, number_of_keys):
        bytes_array = xor_bytes_against_single_char(hex_to_bytes(encoded_string_hex), chr(single_char_key))
        euclidian_distance_key[single_char_key] = euclidian_distance(calculate_letter_frequency(bytes_array))

        print("Key:", single_char_key, ", Distance:", (euclidian_distance_key[single_char_key]))


if __name__ == '__main__':
    s1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print_as_base64(hex_to_bytes(s1))
    s21 = '1c0111001f010100061a024b53535009181c'
    s22 = '686974207468652062756c6c277320657965'
    print("{:x}".format(xor(s21, s22)))
    s3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'


    LETTER_FREQUENCY_STANDARD = {
        'A': 8.55, 'K': 0.81, 'U': 2.68, 'B': 1.60,
        'L': 4.21, 'V': 1.06, 'C': 3.16, 'M': 2.53,
        'W': 1.83, 'D': 3.87, 'N': 7.17, 'X': 0.19,
        'E': 12.1, 'O': 7.47, 'Y': 1.72, 'F': 2.18,
        'P': 2.07, 'Z': 0.11, 'G': 2.09, 'Q': 0.10,
        'H': 4.96, 'R': 6.33, 'I': 7.33, 'S': 6.73,
        'J': 0.22, 'T': 8.94
    }
    characters_n_bit = 128
    LETTERS_IN_ALPHABET = 26

    get_euclidian_distance_for_multiple_keys(s3, characters_n_bit)


