import secrets
import time
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad

def benchmark_aes(test_message):
    key_sizes = [128, 192, 256]
    average_encryption_times = []
    average_decryption_times = []

    for key_size in key_sizes:
        # Generate AES keys
        aes_key = get_random_bytes(key_size // 8)
        intializationVector = get_random_bytes(16)

        # Encryption
        encryption_times = []

        for _ in range(100):
            start_time = time.time()

            aes_cipher = AES.new(aes_key, AES.MODE_CBC, intializationVector)

            plaintext = test_message[:-(len(test_message) % 16)].encode('utf-8')
            plaintext = pad(test_message.encode('utf-8'), AES.block_size)

            ciphertext = aes_cipher.encrypt(plaintext)

            end_time = time.time()
            elapsed_time = end_time - start_time
            encryption_times.append(elapsed_time)

        average_encryption_time = sum(encryption_times) / len(encryption_times)
        average_encryption_times.append(average_encryption_time)

        # Decryption
        decryption_times = []

        for _ in range(100):
            start_time = time.time()

            decipher = AES.new(aes_key, AES.MODE_CBC, intializationVector)

            decrypted = decipher.decrypt(ciphertext)

            # Unpad the decrypted plaintext
            plaintext = unpad(decrypted, AES.block_size).decode('utf-8')

            end_time = time.time()
            elapsed_time = end_time - start_time
            decryption_times.append(elapsed_time)

        average_decryption_time = sum(decryption_times) / len(decryption_times)
        average_decryption_times.append(average_decryption_time)

        print(f"AES {key_size}-bit Average Encryption Time = {average_encryption_time:.6f} seconds")
        print(f"AES {key_size}-bit Average Decryption Time = {average_decryption_time:.6f} seconds\n")
        
def benchmark_rsa(test_message):
    key_sizes = [1024, 2048, 4096]
    average_encryption_times = []
    average_decryption_times = []

    for key_size in key_sizes:
        # Generate RSA keys
        rsa_key = RSA.generate(key_size)

        # Encryption
        encryption_times = []

        for _ in range(100):
            start_time = time.time()

            cipher = PKCS1_OAEP.new(rsa_key)
            ciphertext = cipher.encrypt(test_message.encode('utf-8'))

            end_time = time.time()
            elapsed_time = end_time - start_time
            encryption_times.append(elapsed_time)

        average_encryption_time = sum(encryption_times) / len(encryption_times)
        average_encryption_times.append(average_encryption_time)

        # Decryption
        decryption_times = []

        for _ in range(100):
            start_time = time.time()

            plaintext = cipher.decrypt(ciphertext).decode('utf-8')

            end_time = time.time()
            elapsed_time = end_time - start_time
            decryption_times.append(elapsed_time)

        average_decryption_time = sum(decryption_times) / len(decryption_times)
        average_decryption_times.append(average_decryption_time)

        print(f"RSA {key_size}-bit Average Encryption Time = {average_encryption_time:.6f} seconds")
        print(f"RSA {key_size}-bit Average Decryption Time = {average_decryption_time:.6f} seconds\n")
    
def main():
    messageIn = input("Enter test value: ")
    benchmark_aes(messageIn)
    benchmark_rsa(messageIn)
        
if __name__ == "__main__":
        main()