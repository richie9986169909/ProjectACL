import random
from hashlib import md5
from Crypto.Cipher import AES
from os import urandom
import rsa
# import docx
# import PyPDF2


def get_keys():
    public_key, private_key = rsa.newkeys(128)
    print(public_key)
    print(private_key)
    pub_key = public_key.save_pkcs1()
    pri_key = private_key.save_pkcs1()
    pub_key_str = pub_key.decode()
    pri_key_str = pri_key.decode()
    return pub_key_str, pri_key_str


def derive_key_and_iv(password, salt, key_length, iv_length):  # derive key and IV from password and salt.
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest()  # obtain the md5 hash value
        d += d_i
    return d[:key_length], d[key_length:key_length + iv_length]


def rsa_encryption(in_file, out_file, public_key, key_length=32):
    bs = AES.block_size  # 16 bytes
    salt = urandom(bs)  # return a string of random bytes
    password = str(random.randint(1000, 10000))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt)
    finished = False

    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:  # final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))
    new_public_key = rsa.PublicKey.load_pkcs1(public_key.encode())
    enc_text = rsa.encrypt(password.encode(), new_public_key)
    print(password)
    return enc_text


def rsa_decryption(in_file, out_file, enc_text, private_key, key_length=32):
    new_private_key = rsa.PrivateKey.load_pkcs1(private_key.encode())
    dec_text = rsa.decrypt(enc_text, new_private_key)
    dec_text = dec_text.decode()
    # print('dec_text', dec_text)
    bs = AES.block_size
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(str(dec_text), salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(bytes(x for x in chunk))


# keys = get_keys()
# print(keys[0])
# print(keys[1])
# # infile = 'testing_file.txt'
# infile = 'java.docx'
# outfile = 'encrypted.docx'
#
# with open(infile, 'rb') as in_file1, open(outfile, 'wb') as out_file1:
#     enc_file = rsa_encryption(in_file1, out_file1, keys[0])
# #
# print(enc_file)
# print(type(enc_file))
#
#
# infile = 'encrypted.docx'
# outfile = 'decrypted.docx'
#
#
# with open(infile, 'rb') as in_file1, open(outfile, 'wb') as out_file1:
#     rsa_decryption(in_file1, out_file1, enc_file, keys[1])
#
#
# attribute = "125655"

# result = [ord(a) ^ ord(b) for a, b in zip(key, attribute)]
# print("result", result)


# result = [chr(ord(a) ^ ord(b)) for a, b in zip(keys[0], attribute)]
# # print("result", result)
#
# result2 = [chr(ord(a) ^ ord(b)) for a, b in zip(result, attribute)]
# print("result2", result2)
#
# result2 = [chr(ord(a) ^ ord(b)) for a, b in zip(result, keys[0])]
# print("result2", result2)
