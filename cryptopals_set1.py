import base64
import string
import math
from builtins import bytes
from typing import List

import enchant

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


def convert_hex_to_base_64(unencoded: str):
    """
    Return a hex-string in base64 encoding.

    >>> convert_hex_to_base_64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    return bytes_to_base64(hex_to_bytes(unencoded))


def hex_to_bytes(input_hex: str) -> bytes:
    return bytes.fromhex(input_hex)


def bytes_to_base64(stuff: bytes) -> bytes:
    return base64.b64encode(stuff)


def xor(hex_1: str, hex_2: str) -> hex:
    """
    xor two hex inputs against one another.

    :param hex_1:
    :param hex_2:
    :return: xor of inputs

    >>> xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    10140548954603607733141837726260044841640313

    Expected test result in hex representation:
    '0x746865206b696420646f6e277420706c6179'
    """

    return int(hex_1, 16) ^ int(hex_2, 16)


def single_byte_xor(encrypted: str):
    r"""
    :param encrypted:
    :return:

    >>> single_byte_xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    bytearray(b"Cooking MC\'s like a pound of bacon")
    """
    all_decrypted: List[bytearray] = xor_against_all_chars(hex_to_bytes(encrypted))
    letter_frequencies: List[List[float]] = [get_letter_frequency(d) for d in all_decrypted]
    euclidian_distances: List[float] = [euclidian_distance(f) for f in letter_frequencies]
    dictionary = enchant.Dict("en_US")
    for i in range(0, len(all_decrypted)):
        if euclidian_distances[i] < 15 and has_word(all_decrypted[i], dictionary):
            return all_decrypted[i]


def xor_against_all_chars(encrypted: bytes) -> List[bytearray]:
    return [(xor_bytes_to_char(encrypted, chr(i))) for i in range(0, 128)]


def xor_bytes_to_char(our_bytes: bytes, other: chr) -> bytearray:
    return bytearray([(one_byte ^ ord(other)) for one_byte in our_bytes])


def xor_byte_to_char(our_byte: int, other: chr) -> int:
    return our_byte ^ ord(other)


def get_letter_frequency(decoded_bytes: bytes) -> List[float]:
    letter_frequency = create_list_zeros(LETTERS_IN_ALPHABET)
    for j in range(LETTERS_IN_ALPHABET):
        letter_frequency[j] = decoded_bytes.count(bytes(chr(65 + j), 'ASCII'))
        letter_frequency[j] += decoded_bytes.count(bytes(chr(97 + j), 'ASCII'))

    sum_letters = sum(letter_frequency)
    if sum_letters != 0:
        letter_frequency = [absolute / sum_letters * 100 for absolute in letter_frequency]

    return letter_frequency


def euclidian_distance(lttr_frqncy: list) -> float:
    sum_distance = 0
    for letter in range(len(lttr_frqncy)):
        standard_frequency_of_letter = LETTER_FREQUENCY_STANDARD[string.ascii_uppercase[letter]]
        sum_distance += (standard_frequency_of_letter - lttr_frqncy[letter]) ** 2 / standard_frequency_of_letter

    return math.sqrt(sum_distance)


def bitstring(str_input: str) -> str:
    bytes_list_1 = [b for b in str_input.encode('utf-8')]
    return ''.join(format(x, '08b') for x in bytes_list_1)


def create_list_zeros(length_list: int) -> list:
    return [0] * length_list


def get_euclidian_distance_for_multiple_keys(encoded_string_hex: string, number_of_keys: int = 128):
    euclidian_distances = [{} for _ in range(number_of_keys)]

    for key in range(0, number_of_keys):
        decrypted_bytes_array = xor_bytes_to_char(hex_to_bytes(encoded_string_hex), chr(key))
        euclidian_distances[key]["decrypted"] = decrypted_bytes_array
        euclidian_distances[key]["distance"] = euclidian_distance(get_letter_frequency(decrypted_bytes_array))
        euclidian_distances[key]["encrypted"] = encoded_string_hex
        euclidian_distances[key]["key"] = key

    return euclidian_distances


def get_key_with_minimum_distance(encoded_string_hex: string) -> int:
    ed = get_euclidian_distance_for_multiple_keys(encoded_string_hex)
    minimum_key_solution = min(ed, key=lambda x: x["distance"])
    return minimum_key_solution["key"]


def has_word(chars: bytes, d: enchant.Dict) -> bool:
    split_to_words = str(chars).split(" ")
    try:
        return any((d.check(seq) for seq in split_to_words))
    except:
        return False


def decrypt_files_with_keys(encrypted_file: str) -> list[dict]:
    r"""
    read strings from file and decrypt them vs a single char
    only one of them should yield a reasonable output

    :param encrypted_file:
    :return: list of dicts, each dict containing decrypted string of the encrypted string with best critera:
    - small euclidian distance
    - contains real word

    >>> decrypt_files_with_keys('encrypted.txt')
    [{'decrypted': bytearray(b'Now that the party is jumping\n'), 'distance': 11.624746634464799, 'encrypted': '7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f', 'key': 53}]
    """

    with open(encrypted_file, "r") as f:
        encrypted_lines = f.read().splitlines()
    decryptions = []
    for line in encrypted_lines:
        decryptions += get_euclidian_distance_for_multiple_keys(line)
    good_guesses = [guess for guess in decryptions if guess["distance"] < 15]

    d = enchant.Dict("en_US")

    return [guess for guess in good_guesses if has_word(guess, d)]


def encrypt_string_repeated_xor(plaintext: string, key: string) -> string:
    r"""
    read string from file and encrypt it with the key

    :param plaintext:
    :param key:
    :return: decrypted string

    >>> encrypt_string_repeated_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE')
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    """

    bytes_plain = plaintext.encode('utf-8')

    list_integers = [xor_byte_to_char(b, key[i % len(key)])
                     for i, b in enumerate(bytes_plain)]

    return ''.join(format(x, '02x') for x in list_integers)


def hamming_distance(str1: str, str2: str) -> int:
    str_bit_1 = bitstring(str1)
    str_bit_2 = bitstring(str2)

    count = 0
    for i in range(len(str_bit_1)):
        if str_bit_1[i] != str_bit_2[i]:
            count += 1
    return count


def guess_keysize(cypher: str) -> int:
    hamming_distances = {
        (hamming_distance(cypher[0:i], cypher[i: 2 * i])
         + hamming_distance(cypher[2 * i: 3 * i], cypher[3 * i:4 * i])
         + hamming_distance(cypher[4 * i: 5 * i], cypher[5 * i:6 * i])
         + hamming_distance(cypher[6 * i: 7 * i], cypher[7 * i:8 * i])
         ) / (i * 4): i
        for i in range(2, 41)
    }
    return hamming_distances[min(hamming_distances)]


def read_file_wo_linebreaks(filename: str):
    with open(filename, "r") as f:
        encrypted_lines = f.readlines()
    encrypted_without_linebreaks = [line.rstrip() for line in encrypted_lines]
    return "".join(encrypted_without_linebreaks)


def get_key_size_blocks_hex(cipher: str, keysize: int) -> List[str]:
    blocks = [""] * keysize
    for i, c in enumerate(cipher):
        blocks[i % keysize] += c

    blocks = list(map(lambda block: block.encode('UTF-8').hex(), blocks))
    return blocks


if __name__ == '__main__':
    import doctest

    doctest.testmod()

#     s5 = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
#     key5 = "ICE"
#     s6 = ''
#
#
# print(hamming_distance("this is a test", "wokka wokka!!!"))
# encrypted = read_file_wo_linebreaks(r"task6_encrypted.txt")
# print(guess_keysize(encrypted))
#
# d = enchant.Dict("en_US")
# for i in range(2, 41):
#     hex_blocks = get_key_size_blocks_hex(encrypted, i)
#
#     solutions = [get_key_with_minimum_distance(b) for b in hex_blocks]
#     solution_string_block = [""] * i
#
#     for i, block in enumerate(hex_blocks):
#         solution_string_block[i] = xor_bytes_to_char(hex_to_bytes(block), chr(solutions[i]))

# print(list(zip([d.decode('utf-8') for d in solution_string_block])))
