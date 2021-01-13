from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(iv, data, key):

    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8)
    ct_bytes = cipher.encrypt(data)

    return ct_bytes


def decrypt(iv, data, key):

    try:
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8)
        pt = cipher.decrypt(data)
        return pt

    except (ValueError, KeyError):
        print("Incorrect decryption")


if __name__ == "__main__":

    # Cifrar
    iv = b"\x00" * 16
    data = b"\x00" * 516

    # f186e8d41d1df599f3f979b97973cb00
    key = bytes.fromhex("f186e8d41d1df599f3f979b97973cb00")
    
    print(key)

    ct = encrypt(iv, data, key)

    print("data:", data.hex())
    print("key:", key.hex())
    print("iv :", iv.hex())
    print("ct :", ct.hex())

    # Descifrar
    pt = decrypt(iv, ct, key)
    print("pt :", pt.hex())
