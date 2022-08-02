from base64 import b64decode, decode
import email
import random
import string
from Crypto.Cipher import AES
from more_itertools import padded
import os
from numpy import block

from pyrsistent import b
from requests import get
from set1 import is_ecb_encrypted

def bytes_xor(string1:bytes, string2:bytes) -> bytes:
    assert len(string1) == len(string2)
    return bytes([string1[i] ^ string2[i] for i in range(len(string1))])

def pkcs7(text:bytes, blocksize:int) -> bytes:
    pad:int = blocksize - (len(text) % blocksize)
    return text + bytes([pad] * pad)

def pkcs7_unpad(text:bytes) -> bytes:
    pad = text[-1]
    if pad > 16:
        return text
    for i in range(1, pad+1):
        if text[-i] != pad:
            return text
    return text[:-pad]

def cbc_encrypt(plaintext:bytes, key:bytes, iv:bytes) -> bytes:
    blocksize = len(iv)
    padded_text = pkcs7(plaintext, blocksize)
    ebc_cipher = AES.new(key, AES.MODE_ECB)

    prev = iv
    ciphertext = b''
    for i in range(len(padded_text) // blocksize):
        ciphertext += ebc_cipher.encrypt(bytes_xor(prev, padded_text[i*blocksize:(i+1)*blocksize]))
        prev = ciphertext[i*blocksize:(i+1)*blocksize]
    
    return ciphertext

def cbc_decrypt(ciphertext:bytes, key:bytes, iv:bytes) -> bytes:
    blocksize = len(iv)
    ebc_cipher = AES.new(key, AES.MODE_ECB)

    prev = iv
    plaintext = b''
    for i in range(len(ciphertext) // blocksize):
        plaintext += bytes_xor(ebc_cipher.decrypt(ciphertext[i*blocksize:(i+1)*blocksize]), prev)
        prev = ciphertext[i*blocksize:(i+1)*blocksize]
    
    return pkcs7_unpad(plaintext)

def ecb_encrypt(plaintext:bytes, key:bytes) -> bytes:
    padded_text:bytes = pkcs7(plaintext, len(key))
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    return ecb_cipher.encrypt(padded_text)

def ecb_decrypt(ciphertext:bytes, key:bytes) -> bytes:
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    return ecb_cipher.decrypt(ciphertext)

def split_bytes_by_blocksize(text:bytes, blocksize:int = 16) -> list[bytes]:
    blocks = [text[i*blocksize:(i+1)*blocksize] for i in range(len(text) // blocksize)]
    if len(text) % blocksize != 0:
        blocks.append(text[-(len(text) % blocksize):])
    return blocks

class ECB_Oracle:
    data = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK'''

    def __init__(self):
        self.key = os.urandom(16)
        self.front_padding:bytes = os.urandom(random.randint(2, 30))

    
    def encrypt(self, msg:str='', front_padding:bool=False) -> bytes:
        plaintext:bytes = b64decode(self.data)
        to_encrypt:bytes = msg.encode() + plaintext
        if front_padding:
            to_encrypt = self.front_padding  + to_encrypt
        return ecb_encrypt(to_encrypt, self.key)

def ecb_get_one_more_byte(oracle: ECB_Oracle, blocksize=16, has_front_padding=False, first_different_block=-1, needed_front_padding_len=-1) -> str:
    
    ciphertext = oracle.encrypt()
    plaintext_length = len(ciphertext)

    for i in range(blocksize):
        length = len(cipher.encrypt('A'*i))
        if length != plaintext_length:
            plaintext_length -= i
            break
    
    if has_front_padding:
        plaintext_length -= first_different_block * blocksize + (blocksize - needed_front_padding_len)

    known_plaintext = ''
    for _ in range(plaintext_length):
        padding_len = blocksize - (len(known_plaintext) % blocksize) - 1
        if has_front_padding:
            padding_len -= first_different_block * blocksize + (blocksize - needed_front_padding_len)
        padding = 'A'*padding_len
        
        new_ciphertext = cipher.encrypt(padding)

        for i in range(256):
            testing_msg = padding + known_plaintext + chr(i)
            encrypted_testing_msg = cipher.encrypt(testing_msg)
            if encrypted_testing_msg[:len(testing_msg)] == new_ciphertext[:len(testing_msg)]:
                if (len(known_plaintext) != 138):
                    known_plaintext += chr(i)
                    break
            if (i == 255):
                print("Failed to find the next byte")
                exit(1)

    return known_plaintext

class Profile_Manager:
    def __init__(self):
        self.aes_key:bytes = os.urandom(16)
    
    @staticmethod
    def profile_for(email:str) -> str:
        if ('&' in email) or ('=' in email):
            raise ValueError('Invalid email')
        return 'email=' + email + '&uid=10' + '&role=user'

    def encrypt(self, email:str) -> bytes:
        return ecb_encrypt(self.profile_for(email).encode(), self.aes_key)
    
    def decrypt(self, ciphertext:bytes) -> dict[str, str]:
        profile = ecb_decrypt(ciphertext, self.aes_key)
        profile = pkcs7_unpad(profile).decode()  
        return self.decode_profile(profile)

    @staticmethod
    def decode_profile(encoded_string: str) -> dict[str, str]:
        elements = encoded_string.split('&')
        dict = {}
        for element in elements:
            k, v = element.split('=')
            dict[k] = v
        return dict

def get_front_padding_len_from_oracle(oracle: ECB_Oracle, blocksize=16) -> (int, int):
    clean_ciphertext = oracle.encrypt(front_padding=True)
    one_byte_padding_ciphertext = oracle.encrypt(msg='A', front_padding=True)

    # Find the first block that is different from the clean ciphertext
    # edge case: padding is a multiple of blocksize, will find a block of 'A's
    first_different_block = -1
    for i in range(len(clean_ciphertext) // blocksize + 1):
        if clean_ciphertext[i*blocksize:(i+1)*blocksize] != one_byte_padding_ciphertext[i*blocksize:(i+1)*blocksize]:
            first_different_block = i
            break
    assert first_different_block != -1
    
    # edge case padding_len = 0
    padding_len = 0
    for i in range(1, blocksize):
        padding_ciphertxt = oracle.encrypt(msg='A'*i, front_padding=True)
        if padding_ciphertxt[first_different_block*blocksize:(first_different_block+1)*blocksize] == clean_ciphertext[first_different_block*blocksize:(first_different_block+1)*blocksize]:
            padding_len = i
            break
    
    return first_different_block, padding_len

if __name__ == '__main__':

    # #### challenge 9 ####
    # '''
    # Implement PKCS#7 padding
    # A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

    # One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

    # So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

    # "YELLOW SUBMARINE"
    # ... padded to 20 bytes would be:

    # "YELLOW SUBMARINE\x04\x04\x04\x04"
    # '''
    # print("=" * 50)
    # assert(pkcs7(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')
    # assert(pkcs7_unpad(b'YELLOW SUBMARINE\x04\x04\x04\x04') == b'YELLOW SUBMARINE')
    # print("PCKS#7 padding verified")


    # #### challenge 10 ####
    # '''
    # Implement CBC mode
    # CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

    # In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

    # The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

    # Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

    # The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
    # '''
    # print("=" * 50)
    # with(open("set2_challenge2.txt", "r")) as f:
    #     ciphertext = b64decode(f.read())
    #     plaintext = cbc_decrypt(ciphertext, "YELLOW SUBMARINE".encode(), b'\x00'*16)
    #     assert(ciphertext == cbc_encrypt(plaintext, "YELLOW SUBMARINE".encode(), b'\x00'*16))
    #     print(f"CBC mode implemented correctly")
    #     print(f"Plaintext: {plaintext}")

    # #### challenge 11 ####
    # '''
    # An ECB/CBC detection oracle
    # Now that you have ECB and CBC working:

    # Write a function to generate a random AES key; that's just 16 random bytes.

    # Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

    # The function should look like:

    # encryption_oracle(your-input)
    # => [MEANINGLESS JIBBER JABBER]
    # Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

    # Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

    # Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
    # '''
    # print("=" * 50)
    # plaintext = input("What do you want to encrypt? ")
    # plaintext = os.urandom(random.randint(5, 10)) + bytearray(plaintext, 'utf-8') + os.urandom(random.randint(5, 10))
    # encryption_methods = ''
    # for i in range(random.randint(30, 50)):
    #     key = os.urandom(16)
    #     if random.randint(0, 1):
    #         encrypted_text = ecb_encrypt(plaintext, key)
    #         encryption_methods = 'ECB'
    #     else:
    #         iv = os.urandom(16)
    #         encrypted_text = cbc_encrypt(plaintext, key, iv)
    #         encryption_methods = 'CBC'

    #     if (is_ecb_encrypted(encrypted_text)[0] and encryption_methods == 'CBC'):
    #         print(f"Detection Failed. The encryption method is {encryption_methods}")
    #         print(f"Encrypted text: {encrypted_text}")
    #         print(f"Key: {key}")
    #         print(f"iv: {iv}")
    #         exit(1)
    # print(f"ECB/CBC detection test passed!")
                
    #### challenge 12 ####
    '''
    Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

    Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK
    Spoiler alert.
    Do not decode this string now. Don't do it.

    Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

    What you have now is a function that produces:

    AES-128-ECB(your-string || unknown-string, random-key)
    It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

    Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
    Detect that the function is using ECB. You already know, but do this step anyways.
    Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
    Repeat for the next byte.
    '''
    print("=" * 50)
    cipher = ECB_Oracle()
    ciphertext = cipher.encrypt()
    
    # find plaintext length 
 
    assert known_plaintext == b64decode(cipher.data).decode()
    print("Successfully decrypted the ciphertext with 'byte-at-a-time decryption\n")
    print(f"Plaintext: {known_plaintext}")

    # #### challenge 13 ####
    # '''
    # Write a k=v parsing routine, as if for a structured cookie. The routine should take:

    # foo=bar&baz=qux&zap=zazzle
    # ... and produce:

    # {
    # foo: 'bar',
    # baz: 'qux',
    # zap: 'zazzle'
    # }
    # (you know, the object; I don't care if you convert it to JSON).

    # Now write a function that encodes a user profile in that format, given an email address. You should have something like:

    # profile_for("foo@bar.com")
    # ... and it should produce:

    # {
    # email: 'foo@bar.com',
    # uid: 10,
    # role: 'user'
    # }
    # ... encoded as:

    # email=foo@bar.com&uid=10&role=user
    # Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

    # Now, two more easy functions. Generate a random AES key, then:

    # Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    # Decrypt the encoded user profile and parse it.
    # Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.`
    # '''
    # print("=" * 50)
    # manager = Profile_Manager()
    # hacker_email = "e@example.com"
    # print(f"Crafted Email: {hacker_email}")
    # crafted_profile = manager.profile_for(hacker_email)
    # print(f"Crafted Profile by block: {split_bytes_by_blocksize(crafted_profile.encode())}")
    # encrypted_hacker_profile = manager.encrypt(hacker_email)
    # crafted_blocks = split_bytes_by_blocksize(encrypted_hacker_profile)

    # email_contains_admin = pkcs7(b"admin", 16)
    # padding_front = b'A' * 10
    # print(f"Email contains admin: {email_contains_admin}")
    # print(f"Email contains admin by block: {split_bytes_by_blocksize(b'email=' + padding_front + email_contains_admin)}")
    # email_contains_admin_profile = manager.encrypt(padding_front.decode() + email_contains_admin.decode())
    # admin_blocks = split_bytes_by_blocksize(email_contains_admin_profile)

    # admin_user = manager.decrypt(b''.join(crafted_blocks[:-1]) + admin_blocks[1])
    # print(f"Admin User: {admin_user}")
    # assert admin_user == {'email': hacker_email, 'uid': '10', 'role': 'admin'}

    ##### challenge 14 #####
    '''
    Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    Same goal: decrypt the target-bytes.
    '''
    print("=" * 50)
    oracle = ECB_Oracle()
    
    # Assumption 
    first_different_block, padding_len = get_front_padding_len_from_oracle(oracle)
            

