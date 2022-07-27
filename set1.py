import base64
from logging import raiseExceptions
from re import I
from Crypto.Util.strxor import *
from Crypto.Util.number import *
from binascii import unhexlify, hexlify
from Crypto.Cipher import AES

#### helpers ####
# def score_in_english(decoded_string):
#     freq = {}
#     freq[' '] = 700000000
#     freq['e'] = 390395169
#     freq['t'] = 282039486
#     freq['a'] = 248362256
#     freq['o'] = 235661502
#     freq['i'] = 214822972
#     freq['n'] = 214319386
#     freq['s'] = 196844692
#     freq['h'] = 193607737
#     freq['r'] = 184990759
#     freq['d'] = 134044565
#     freq['l'] = 125951672
#     freq['u'] = 88219598
#     freq['c'] = 79962026
#     freq['m'] = 79502870
#     freq['f'] = 72967175
#     freq['w'] = 69069021
#     freq['g'] = 61549736
#     freq['y'] = 59010696
#     freq['p'] = 55746578
#     freq['b'] = 47673928
#     freq['v'] = 30476191
#     freq['k'] = 22969448
#     freq['x'] = 5574077
#     freq['j'] = 4507165
#     freq['q'] = 3649838
#     freq['z'] = 2456495
    
#     score = 0
#     for c in decoded_string:
#         score += freq[chr(c).lower()] if (chr(c).lower() in freq.keys()) else 0
#     return score

def score_in_english(decoded_string):
    ascii_text_chars = list(range(97, 122)) + [32]
    return sum([x in ascii_text_chars for x in decoded_string])

def is_probably_text(plaintext, ascii_bytes_ratio=0.7):
    score = score_in_english(plaintext)
    return ((score / len(plaintext)) > ascii_bytes_ratio), score

def int_to_bytes(m):
     return m.to_bytes(int(m.bit_length()/8 + 1), byteorder='big')

def str_to_bin(string):
    return ''.join(bin(x)[2:] for x in string.encode())

#### challenge 1 ####
def hex_to_base64(hex_string):
    return base64.b64encode(unhexlify(hex_string))

#### challenge 2 ####
def fixed_xor(hex_string1, hex_string2):
    assert(len(hex_string1) == len(hex_string2))
    return bytes(x ^ y for x, y in zip(unhexlify(hex_string1), unhexlify(hex_string2))).hex()

#### challenge 3 ####
def single_byte_xor(hex_encoded_string, ascii_bytes_ratio=0.7):
    max_score = -1
    key = None 
    english_plaintext = None

    for i in range(256):
        current_plaintext = bytes([x ^ y for x, y in zip(unhexlify(hex_encoded_string), int_to_bytes(i) * len(hex_encoded_string))])
        is_english, current_score = is_probably_text(current_plaintext, ascii_bytes_ratio)

        if is_english and current_score > max_score:
            max_score = current_score
            english_plaintext = current_plaintext
            key = i

    try:
        key = int_to_bytes(key)
    except:
        raiseExceptions('No plaintext found')
    finally:
        return english_plaintext, key, max_score

#### challenge 4 ####
def challenge_4_solver(file_path):
    highest_score = -1

    with open(file_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            try:
                plaintext, key, score = single_byte_xor(line.strip())
            except:
                continue

            if score > highest_score:
                highest_score = score
                highest_plaintext = plaintext
                highest_key = key

    return highest_plaintext, highest_key, highest_score

#### challenge 5 ####
def repeating_key_xor(plaintext, key):
    return bytes([x ^ y for x, y in zip(plaintext.encode(), (key*len(plaintext)).encode())]).hex()

#### challenge 6 ####
def hamming_distance(plaintext1, plaintext2):
    assert(len(plaintext1) == len(plaintext2))
    return sum(bin(x ^ y).count('1') for x, y in zip(plaintext1.encode(), plaintext2.encode()))

def score_key_size(min_key_size, max_key_size, ciphertext):
    scores = {}
    for key_size in range(min_key_size, max_key_size + 1):
        distance = 0
        prev = None
        for i in range(0, len(ciphertext), key_size):
            if i + key_size > len(ciphertext):
                break
            
            ciphertext_block = ciphertext[i:i+key_size]
            if prev:
                distance += hamming_distance(prev, ciphertext_block)
            prev = ciphertext_block
        
        scores[key_size] = distance / ((len(ciphertext) // key_size - 1) * key_size)
    return scores

def find_key_size(ciphertext, number_of_key_sizes):
    min_key_size = 2
    max_key_size = 40
    scores = score_key_size(min_key_size, max_key_size, ciphertext)
    sorted_scores = sorted(scores.items(), key=lambda x: x[1])
    return dict(sorted_scores[:number_of_key_sizes])

def break_repeating_key_xor_with_key_size(ciphertext, key_size):
    key = ''
    try:
        for i in range(key_size):
            ciphertext_block = ciphertext[i:-1:key_size]
            key += single_byte_xor(hexlify(ciphertext_block.encode()))[1].decode()
    except:
        return None, None
    
    return key, unhexlify(repeating_key_xor(ciphertext, key))

def challenge_6_solver(ciphertext, number_of_key_sizes=2):
    key_sizes = find_key_size(ciphertext, number_of_key_sizes)
    answers = []
    for i in key_sizes:
        key, plaintext = break_repeating_key_xor_with_key_size(ciphertext, i)
        if key is not None and is_probably_text(plaintext):
            answers.append((key, plaintext))
    return answers

def is_ecb_encrypted(ciphertext, block_size=16):
    if (len(ciphertext) % block_size != 0):
        return False

    num_blocks = len(ciphertext) // block_size
    blocks  = [ciphertext[i*block_size:(i+1)*block_size] for i in range(num_blocks)]

    return len(set(blocks)) != num_blocks


if __name__ == "__main__":
    #### challenge 1 ####
    '''
    Convert hex to base64
    The string:

    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    Should produce:

    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
    '''
    print("=" * 50)
    if (hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d') == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'):
        print("Hex to Base64: passed")
    else:
        print("Hex to Base64: failed")

    #### challenge 2 ####
    '''
    Fixed XOR
    Write a function that takes two equal-length buffers and produces their XOR combination.

    If your function works properly, then when you feed it the string:

    1c0111001f010100061a024b53535009181c
    ... after hex decoding, and when XOR'd against:

    686974207468652062756c6c277320657965
    ... should produce:

    746865206b696420646f6e277420706c6179
    '''
    print("=" * 50)
    if (fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965') == '746865206b696420646f6e277420706c6179'):
        print("Fixed XOR: passed")
    else:
        print("Fixed XOR: failed")

    #### challenge 3 ####
    '''
    Single-byte XOR cipher
    The hex encoded string:

    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    has been XOR'd against a single character. Find the key, decrypt the message.

    You can do this by hand. But don't: write code to do it for you.

    How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
    '''
    print("=" * 50)
    print("Single-byte XOR Cipher: (plaintext, key, score)")
    print(single_byte_xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))

    #### challenge 4 ####
    '''
    Detect single-character XOR
    One of the 60-character strings in this file has been encrypted by single-character XOR.

    Find it.

    (Your code from #3 should help.)
    '''
    print("=" * 50)
    print("Detect single-byte XOR: (plaintext, key, score)")
    file_path = './set1_challenge4.txt'
    print(challenge_4_solver(file_path))

    #### challenge 5 ####
    '''
    Implement repeating-key XOR
    Here is the opening stanza of an important work of the English language:

    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal
    Encrypt it, under the key "ICE", using repeating-key XOR.

    In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

    It should come out to:

    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
    '''
    print("=" * 50)
    if (repeating_key_xor('Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal', 'ICE') == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'):
        print("Implement repeating-key XOR: passed")
    else:
        print("Implement repeating-key XOR: failed")
    
    #### challenge 6 ####
    '''
    Break repeating-key XOR

    There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

    Decrypt it.

    Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
    this is a test
    and
    wokka wokka!!!
    is 37. Make sure your code agrees before you proceed.
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
    This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
    '''
    print("=" * 50)
    assert(37 == hamming_distance('this is a test', 'wokka wokka!!!'))
    # with(open('set1_challenge6.txt', 'r')) as f:
    with(open('./set1_challenge6.txt', 'r')) as f:
        ciphertext = base64.b64decode(f.read()).decode()
        answers = challenge_6_solver(ciphertext, 5)
        print(f"{len(answers)} possible answer(s)")
        for a in answers:
            print(f"Key: {a[0]}\nPlaintext: {a[1]}")

    ### challenge 7 ####
    '''
    AES in ECB mode
    The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
    "YELLOW SUBMARINE".
    (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

    Decrypt it. You know the key, after all.

    Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
    '''
    print("=" * 50)
    with(open('./set1_challenge7.txt', 'r')) as f:
        key = 'YELLOW SUBMARINE'
        ciphertext = base64.b64decode(f.read())
        plaintext = AES.new(key.encode(), AES.MODE_ECB).decrypt(ciphertext)
        print(f"128-bit AES ECB decryption\n {plaintext}")

    #### challenge 8 ####
    print("=" * 50)
    '''
    Detect AES in ECB mode
    In this file are a bunch of hex-encoded ciphertexts.
    
    One of them has been encrypted with ECB.
    Detect it.
    
    Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
    '''
    with(open('./set1_challenge8.txt', 'r')) as f:
        for line in f.readlines():
            ciphertext = unhexlify(line.strip())
            if (is_ecb_encrypted(ciphertext)):
                print(f"{ciphertext} is ECB encrypted")
