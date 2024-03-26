import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Manager
from Crypto.Cipher import AES
from itertools import product
from itertools import repeat
from functools import partial

found = False

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
s_event = multiprocessing.Event() 

def decrypt_message_v2(key,padMsg9,iv,ciphertext):
    key = bytes.join(b'',key)
    msg = decrypt_message(key,iv,ciphertext)
    return msg

def generate_multiple_lists(list_of_lists,n):
    listTmp = []
    listTmp1 = []
    for i in range(len(list_of_lists[0])):
        listTmp.append(list_of_lists[0][i])
        if len(listTmp) == n:
            listTmp1.append(listTmp)
            listTmp = []
    if len(listTmp) > 0:
        listTmp1.append(listTmp)
    listTmp = []
    listFinal =[]
    listsFinal = []
    list_of_lists.pop(0)
    for elem in listTmp1:
        listFinal.append(elem)
        for elem1 in list_of_lists:
            listFinal.append(elem1)
        listsFinal.append(listFinal)
        listFinal = []

    return listsFinal

def multithreading_decryption(list_of_lists,padMsg9,cyphertext):

    set_cipher(cyphertext)
    cipherTxt1 = bytes.fromhex(cyphertext)
    iv = cipherTxt1[:AES.block_size]
    Manager = multiprocessing.Manager()
    output = Manager.Queue()
    stop_event = Manager.Event()  # Event to signal stopping
    found = False
    processes = []
    listTmp = []
    listTmp1 = []
    for i in range(len(list_of_lists)):
        for comb in list_of_lists[i]:
            listTmp.append(bytes.fromhex(bits_to_hex(comb)))
        listTmp1.append(listTmp)
        listTmp = []
    results = []
    key1 = []
    listTmp1 = listTmp1
    n = len(list_of_lists[0]) // 6
    print("n: ",n)
    listsToElaborate = generate_multiple_lists(listTmp1,n)
    listsToElaborate = []
    listsToElaborate.append(listTmp1)
    for list1 in listsToElaborate:
        process = multiprocessing.Process(target=start_production, args=(list1,padMsg9,cyphertext,output,stop_event))
        process.start()
        processes.append(process)
    print("Processes started")
    print("number of processes: ",len(processes))
    for process in processes:
        process.join()

    while not output.empty():
        result = output.get()
        results.append(result)
    
    return results
    
def start_production(list_of_lists,padMsg9,cyphertext,output,stop_event):
    cipherTxt1 = bytes.fromhex(cyphertext)
    iv = cipherTxt1[:AES.block_size]
    key1 = []
    nKeys = 1000000
    for key in product(*list_of_lists):
        key1.append(key)
        #key1.append(bytes.join(b'',key))
        #key1 = b''
        #for i in range(len(key)):
            #key1 += key[i]
        if(len(key1) == nKeys):
            with multiprocessing.Pool() as pool:
                results = pool.starmap(decrypt_message_v2, zip(key1,repeat(padMsg9),repeat(iv),repeat(cipherTxt1)))
                for result in results:
                    if result == padMsg9:
                        output.put(key1)
                        stop_event.set()
                        break
            key1 = []
            print("number of keys: ",nKeys)
            if found:
                break
        if stop_event.is_set():
            break
   
    return 

def gen_combo_without_threding_test(list_of_lists):

    results = []
    for key in product(*list_of_lists):
        key1 = ''.join(''.join(x) for x in key) 
        results.append(key1)
    return results

