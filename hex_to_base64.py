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


if __name__ == '__main__':
    s1 = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print_as_base64(hex_to_bytes(s1))
    s21 = '1c0111001f010100061a024b53535009181c'
    s22 = '686974207468652062756c6c277320657965'
    print("{:x}".format(xor(s21, s22)))
    s3 = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    euclidian_distance = [0 for key in range(127)]
    letter_frequency = [[0 for letter in range(26)] for key in range(127)]
    letter_frequency_standard = {'A': 8.55, 'K': 0.81, 'U': 2.68, 'B': 1.60,
                        'L': 4.21, 'V': 1.06, 'C': 3.16, 'M': 2.53,
                        'W': 1.83, 'D': 3.87, 'N': 7.17, 'X': 0.19,
                        'E': 12.1, 'O': 7.47, 'Y': 1.72, 'F': 2.18,
                        'P': 2.07, 'Z': 0.11, 'G': 2.09, 'Q': 0.10,
                        'H': 4.96, 'R': 6.33, 'I': 7.33, 'S': 6.73,
                        'J': 0.22, 'T': 8.94}

    for key in range(0, 127):
        bytes_array = xor_bytes_against_single_char(hex_to_bytes(s3), chr(key))

        # sum = 0
        for j in range(26):
            letter_frequency[key][j] = bytes_array.count(bytes(chr(65 + j), 'ASCII'))
            letter_frequency[key][j] += bytes_array.count(bytes(chr(97 + j), 'ASCII'))
            # sum += list_output[key][j]

        sum_letters = sum(letter_frequency[key])
        if sum_letters != 0:
            letter_frequency[key] = [absolute / sum_letters * 100 for absolute in letter_frequency[key]]
        else:
            letter_frequency[key] = [0 for i in range(26)]

        # print(chr(i), i,  (xor_bytes_against_single_char(hex_to_bytes(s3), chr(i)))) #.count(bytes(chr(111), 'ASCII')))

        sum_distance = 0
        for letter in range(26):
            sum_distance += (letter_frequency_standard[string.ascii_uppercase[letter]] - letter_frequency[key][letter]) ** 2

        euclidian_distance[key] = np.sqrt(sum_distance)

        print("Key:", key, ", Distance:", (euclidian_distance[key]))

