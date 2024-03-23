import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Manager
from Crypto.Cipher import AES
from itertools import product


def bits_to_hex(bits):

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

def set_cipher(cipherTmp):
    global cipherTxt
    global ivGlobal
    cipherTxt = bytes.fromhex(cipherTmp)
    ivGlobal = cipherTxt[:AES.block_size]



def decrypt_message(key,iv,cipherTxt):
    #key = bits_to_hex(key)
    #key = bytes.fromhex(key)
    # Extract the IV from the beginning of the ciphertext

    # Create AES cipher object in CBC mode

    cipher1 = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext

    decrypted_data = cipher1.decrypt(cipherTxt[AES.block_size:])
    
    # Unpad the decrypted data
    #unpadded_data = unpad(decrypted_data, AES.block_size)
    
    # Return the unpadded data
    return decrypted_data


def gen_combo_without_threding(list_of_lists,padMsg9,cyphertext):
    set_cipher(cyphertext)
    listTmp = []
    listTmp1 = []
    for i in range(len(list_of_lists)):
        for comb in list_of_lists[i]:
            listTmp.append(bytes.fromhex(bits_to_hex(comb)))
        listTmp1.append(listTmp)
        listTmp = []
    results = []
    print("listTmp1: ",listTmp1)
    for key in product(*listTmp1):
        key1 = bytes.join(b'',list(key))
        msg = decrypt_message(key1)
        if msg == padMsg9:
            results = key1
            print(results)
            break
        
    return results

def gen_combo_without_threding_v2(list_of_lists,padMsg9,output):  
    for key in product(*list_of_lists):
        key1 = bytes.join(b'',list(key))
        msg = decrypt_message(key1)
        if msg == padMsg9:
            results = key1
            print(results)
            break
        
    return results

def decrypt_message_v2(key,padMsg9,iv,ciphertext,output,stop_event):
    msg = decrypt_message(key,iv,ciphertext)
    if msg == padMsg9:
        output.put(key)
        stop_event.set()
    return

def multithreading_decryption(list_of_lists,padMsg9,cyphertext):
    set_cipher(cyphertext)
    cipherTxt1 = bytes.fromhex(cyphertext)
    iv = cipherTxt1[:AES.block_size]
    output = multiprocessing.Queue()
    stop_event = multiprocessing.Event()  # Event to signal stopping
    processes = []
    listTmp = []
    listTmp1 = []
    for i in range(len(list_of_lists)):
        for comb in list_of_lists[i]:
            listTmp.append(bytes.fromhex(bits_to_hex(comb)))
        listTmp1.append(listTmp)
        listTmp = []
    results = []
    for key in product(*listTmp1):
        key1 = bytes.join(b'',list(key))
        process = multiprocessing.Process(target=decrypt_message_v2, args=(key1,padMsg9,iv,cipherTxt1,output,stop_event))
        process.start()
        processes.append(process)
        if(processes.__len__() > 100):
            for process in processes:
                process.join()
            processes = []
        if stop_event.is_set():
            break
    for process in processes:
        process.join()
    
    while not output.empty():
        result = output.get()
        results.append(result)
        
    return results
    

def gen_combo_without_threding_test(list_of_lists):

    results = []
    for key in product(*list_of_lists):
        key1 = ''.join(''.join(x) for x in key) 
        results.append(key1)
    return results

