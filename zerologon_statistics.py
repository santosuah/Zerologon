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

    print("\n[*] Chiper            : AES")
    print("[*] Mode of operation : CFB8 (8-bit cipher feedback)")

    # Initialization vector (16 bytes)
    iv = b"\x00" * 16
    print("[*] IV                :", iv.hex())
    
    # Client challenge (8 bytes)
    challenge = b"\x00" * 8
    print("[*] Client challenge  :", challenge.hex())

    # ---------------- Search ------------------

    print("\n[*] Search in 256 random keys")

    count = 0
    for _ in range(256):

        # Random session key (16 bytes)
        # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NRPC/%5BMS-NRPC%5D.pdf
        # 3.1.4.3.1AES Session-Key
        key = get_random_bytes(16)

        chipertext = encrypt(iv, challenge, key)

        if chipertext == challenge:

            plaintext = decrypt(iv, chipertext, key)
        
            print("\nSession key :", key.hex())
            print("chipertext  :", chipertext.hex())
            print("plaintext   :", plaintext.hex())
    
            count += 1

    print("\n[*] Number of keys found:", count, "\n")
