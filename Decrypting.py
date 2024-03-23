import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Manager
from Crypto.Cipher import AES
from itertools import product

def bits_to_hex(bits):
    # Padding the bits with zeros to make the length a multiple of 4
    while len(bits) % 4 != 0:
        bits = '0' + bits

    # Dictionary mapping binary strings to hexadecimal digits
    binary_to_hex = {
        '0000': '0',
        '0001': '1',
        '0010': '2',
        '0011': '3',
        '0100': '4',
        '0101': '5',
        '0110': '6',
        '0111': '7',
        '1000': '8',
        '1001': '9',
        '1010': 'a',
        '1011': 'b',
        '1100': 'c',
        '1101': 'd',
        '1110': 'e',
        '1111': 'f'
    }

    hex_string = ''
    # Grouping the bits into groups of four and converting each group to hexadecimal
    for i in range(0, len(bits), 4):
        hex_string += binary_to_hex[bits[i:i+4]]

    return hex_string

def decrypt_message(key, ciphertext):
    key = bits_to_hex(key)
    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)
    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:AES.block_size]

    # Create AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext

    decrypted_data = cipher.decrypt(ciphertext[AES.block_size:])
    
    # Unpad the decrypted data
    #unpadded_data = unpad(decrypted_data, AES.block_size)
    
    # Return the unpadded data
    return decrypted_data

def generate_combinations_parallel(args):
    list_of_lists, index, current_combination,padMsg9,cyphertext, output, stop_event,num_workers = args
    if stop_event.is_set():
        return
    if index == len(list_of_lists):
        msg = decrypt_message(current_combination, cyphertext)
        if msg == padMsg9:
            output.put(current_combination)
            stop_event.set()  # Set the stop event to signal other processes to stop
            print(current_combination)
        return
    if index == 1:
        print("num_workers: ",num_workers)
    for chunk in list_of_lists[index]:
        new_combination = current_combination + chunk
        generate_combinations_parallel((list_of_lists, index + 1, new_combination,padMsg9,cyphertext, output, stop_event,num_workers))



def generate_combinations(list_of_lists,padMsg9,cyphertext):
    manager = Manager()
    output = manager.Queue()
    stop_event = manager.Event()  # Event to signal stopping
    executor = ProcessPoolExecutor()

    futures = []
    id = 0
    for chunk in list_of_lists[0]:
        new_combination = chunk
        future = executor.submit(generate_combinations_parallel, (list_of_lists,1, new_combination,padMsg9,cyphertext, output, stop_event,id))
        futures.append(future)
        id += 1

    # Wait for all futures to complete
    print("futurjes: ",len(futures))
    for future in futures:
        future.result()

    # Get results from the output queue
    results = []
    while not output.empty():
        result = output.get()
        results.append(result)

    return results

def gen_combo_without_threding(list_of_lists,padMsg9,cyphertext):
    
    li = ['a', 'b', 'c']
    for comb in product(li, repeat=len(li)):
        print(''.join(comb))
        msg = decrypt_message(''.join(comb), cyphertext)
        if msg == padMsg9:
            results = ''.join(comb)
            print(results)

    return results

def gen_combo_without_threding_test(list_of_lists):

    results = []
    results = list(product(*list_of_lists))
    return results

