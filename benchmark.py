import time
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def benchmark_hmac_generation(message, secret_key, iterations=100):
    start_time = time.time()
    for _ in range(iterations):
        h = SHA256.new(message)
        h.update(secret_key)
    end_time = time.time()
    return (end_time - start_time) / iterations

def benchmark_signature(message, rsa_private_key, rsa_public_key, iterations=100):
    start_time = time.time()
    for _ in range(iterations):
        # Signature generation
        message_hash = SHA256.new(message)
        signature = pkcs1_15.new(rsa_private_key).sign(message_hash)

        # Signature verification
        try:
            message_hash = SHA256.new(message)
            pkcs1_15.new(rsa_public_key).verify(message_hash, signature)
        except (ValueError, TypeError):
            pass
    end_time = time.time()
    signature_generation_time = (end_time - start_time) / iterations

    start_time = time.time()
    for _ in range(iterations):
        message_hash = SHA256.new(message)
        signature = pkcs1_15.new(rsa_private_key).sign(message_hash)

        try:
            message_hash = SHA256.new(message)
            pkcs1_15.new(rsa_public_key).verify(message_hash, signature)
        except (ValueError, TypeError):
            pass
    end_time = time.time()
    signature_verification_time = (end_time - start_time) / iterations

    return signature_generation_time, signature_verification_time

if __name__ == '__main__':
    #message = b'1234567'  # defualt value
    print("Input message: ")
    message = input()
    message = message.encode('utf-8')
    secret_key = b'1234567890123456'  

    hmac_time = benchmark_hmac_generation(message, secret_key)
    print(f'Average time for HMAC generation: {hmac_time:.6f} seconds')

    rsa_private_key = RSA.generate(2048)
    rsa_public_key = rsa_private_key.publickey()

    signature_generation_time, signature_verification_time = benchmark_signature(
        message, rsa_private_key, rsa_public_key)

    print(f'Average time for digital signature generation: {signature_generation_time:.6f} seconds')
    print(f'Average time for digital signature verification: {signature_verification_time:.6f} seconds')