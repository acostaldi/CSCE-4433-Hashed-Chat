import hashlib
import random

def generate_random_message():
    message = bytes([random.randint(0, 255) for _ in range(32)])  # 32 bytes (256 bits)
    return message

def compute_hash(message):
    sha256_hash = hashlib.sha256(message).digest()
    first_8_bits = sha256_hash[:1]  
    return first_8_bits

def find_first_hash_collision():
    hash_dict = {}
    trials = 0

    while True:
        trials += 1
        message = generate_random_message()
        hash_value = compute_hash(message)

        if hash_value in hash_dict:
            # Get the first message that collided
            collided_message = hash_dict[hash_value]
            return message, hash_value, collided_message, trials
        else:
            hash_dict[hash_value] = message

def find_first_hash_collision_a():
    hash_set = set()
    trials = 0

    while True:
        trials += 1
        message = generate_random_message()
        hash_value = compute_hash(message)

        if hash_value in hash_set:
            return message, hash_value, trials
        else:
            hash_set.add(hash_value)

def average_collision_trials(iterations):
    total_trials = 0

    for _ in range(iterations):
        _, _, trials = find_first_hash_collision_a()
        total_trials += trials

    return total_trials / iterations

if __name__ == '__main__':
    print("Starting collision tests")
    # 4(a)
    message1, hash_value, message2, trials = find_first_hash_collision()

    print(f'First collision found after {trials} trials:')
    print(f'Message 1: {message1}')
    print(f'Message 2: {message2}')
    print(f'Hash Value: {hash_value}')

    # 4(b)
    average_trials = average_collision_trials(20)
    print(f'\nAverage number of trials needed to find a collision over {20} iterations: {average_trials:.2f}')