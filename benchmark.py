import secrets
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad

def benchmark_aes_encryption(test_message):
    #Generate AES keys
    aes_key128 = get_random_bytes(16)
    aes_key192 = get_random_bytes(24)
    aes_key256 = get_random_bytes(32)

    intializationVector = get_random_bytes(16)
    
    #Decrypt and measure time
    start_time = time.time()

    aes_cipher128 = AES.new(aes_key128, AES.MODE_CBC, intializationVector)
    aes_cipher192 = AES.new(aes_key192, AES.MODE_CBC, intializationVector)
    aes_cipher256 = AES.new(aes_key256, AES.MODE_CBC, intializationVector)

    plaintext = test_message[:-(len(test_message) % 16)].encode('utf-8')
    plaintext = pad(test_message.encode('utf-8'), AES.block_size)

    ciphertext128 = aes_cipher128.encrypt(plaintext)
    ciphertext192 = aes_cipher192.encrypt(plaintext)
    ciphertext256 = aes_cipher256.encrypt(plaintext)
    
    print("Encrypted 128-bit:", ciphertext128.hex())
    print("Encrypted 192-bit:", ciphertext192.hex())
    print("Encrypted 256-bit:", ciphertext256.hex())
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print("AES Average Encryption time = {:.6f} seconds".format(elapsed_time / 3))

    #Decrypt and measure time
    start_time = time.time()

    decipher128 = AES.new(aes_key128, AES.MODE_CBC, intializationVector)
    decipher192 = AES.new(aes_key192, AES.MODE_CBC, intializationVector)
    decipher256 = AES.new(aes_key256, AES.MODE_CBC, intializationVector)

    decrypted128 = decipher128.decrypt(ciphertext128)
    decrypted192 = decipher192.decrypt(ciphertext192)
    decrypted256 = decipher256.decrypt(ciphertext256)

    #Unpad the decrypted plaintext
    plaintext128 = unpad(decrypted128, AES.block_size).decode('utf-8')
    plaintext192 = unpad(decrypted192, AES.block_size).decode('utf-8')
    plaintext256 = unpad(decrypted256, AES.block_size).decode('utf-8')

    end_time = time.time()

    #Print decrypted values
    print("Decrypted 128-bit:", plaintext128)
    print("Decrypted 192-bit:", plaintext192)
    print("Decrypted 256-bit:", plaintext256)

    #Print the time taken for decryption
    elapsed_time = end_time - start_time
    print("AES Average Encryption time = {:.6f} seconds".format(elapsed_time / 3))

def benchmark_rsa_encryption(test_message):
    #Generate RSA keys
    rsa_key1024 = RSA.generate(1024)
    rsa_key2048 = RSA.generate(2048)
    rsa_key4096 = RSA.generate(4096)

    #Encrypt and measure time
    start_time = time.time()

    cipher1024 = PKCS1_OAEP.new(rsa_key1024)
    cipher2048 = PKCS1_OAEP.new(rsa_key2048)
    cipher4096 = PKCS1_OAEP.new(rsa_key4096)

    ciphertext1024 = cipher1024.encrypt(test_message.encode('utf-8'))
    ciphertext2048 = cipher2048.encrypt(test_message.encode('utf-8'))
    ciphertext4096 = cipher4096.encrypt(test_message.encode('utf-8'))

    print("Encrypted 1024-bit:", ciphertext1024.hex())
    print("Encrypted 2048-bit:", ciphertext2048.hex())
    print("Encrypted 4096-bit:", ciphertext4096.hex())

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("RSA Average Encryption time = {:.6f} seconds".format(elapsed_time / 3))

    #Decrypt and measure time
    start_time = time.time()

    plaintext1024 = cipher1024.decrypt(ciphertext1024).decode('utf-8')
    plaintext2048 = cipher2048.decrypt(ciphertext2048).decode('utf-8')
    plaintext4096 = cipher4096.decrypt(ciphertext4096).decode('utf-8')

    print("Decrypted 1024-bit:", plaintext1024)
    print("Decrypted 2048-bit:", plaintext2048)
    print("Decrypted 4096-bit:", plaintext4096)

    end_time = time.time()

    #Print the time taken for decryption
    elapsed_time = end_time - start_time
    print("RSA Average Decryption time = {:.6f} seconds".format(elapsed_time / 3))

    
def main():
    messageIn = input("Enter test value: ")
    benchmark_aes_encryption(messageIn)
    benchmark_rsa_encryption(messageIn)
        
if __name__ == "__main__":
        main()