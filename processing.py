from itertools import repeat
import multiprocessing
from Crypto.Cipher import AES
import cProfile
MSG_PAIRS_1 = [
    (b'The most important words a man can say are, "I will do better".', 'a1e796da5a4a864aabebb9a348b684686e2f5ca3938834856a9653f4791be390b2c8119375717f37297ce18c546727a8718937bfa0f9aec150eb10085775b50e7bc37846cc804fbfa1b9d307f97f7804'),
    (b'The purpose of a storyteller is not to tell you how to think, but to give you questions to think upon.', '8706f4fd4e7f1f20d5d1702fbcda669b8f6a9ce206e1d3ca8eb949a6a27b83d213f6a001e6aa9cdab83d19c2ff5143c5dbed6a17d1f94bef88231d56f070d96e15491d28ca33d05a484976d8b4940339f5d28ddbddec878ea02a129aa56faebadb020c485b1399367f2890e5e571a7e73e4d2716e4cd71e5a97442145418f612'),
    (b"It's easy to believe in something when you win all the time... The losses are what define a man's faith.", '45d9814d656d847737b8447cff70d6b0d2cfd623085d8150c81b9b3bdd384746ac0e267b858a2bd8362f8e4a24f2dc128225f2ae3da9f857e5e3f3c7ee571d2b20b66d714e4b3f5297aa41cb06f0927be78db2188283746f5cd377e9a54bbe0ec2868c7398ee41152942570ad29a7dcaf358ff45a30993b4e91d6037ca2fe4c0'),
    (b'Sometimes the prize is not worth the costs.', 'd09c3f0c3ccc5e49fd126f2fc4ce5068105a3beeb26dc66e6c332240b4e30917a5001204f58eba0beb2897fdc6ef19b608d0739eee3fa4b9867a39764a2227d0'),
    (b'Sometimes a hypocrite is nothing more than a man in the process of changing.', '889ed26f7615599bed86684af0d2606ab49f2a52efea712f3dff7c3ec37420d2b10ab1f42679363125fb81410e60e34f7c63c26a4c47b6232af542e36bbd3604e31b52db19f07e8cb19e518f32e7b7b415ee757a2bc9186cd91b52b7fb65a05c'),
    (b'Our belief is often strongest when it should be weakest. That is the nature of hope.', 'bf887c305b4771286a050720fe68def9057229245510d6401517262079d96a792d8746b295208e56b5ad12731c0c9ff6ef5c52022c887f40fa935790573040a5bdd19d73d7d92f63724232f870844b059f1f282061867d01fae85e2356a4554acf08d8bc61e798e219c6c52b025e997f'),
    (b"The most important step a man can take it's not the first one, it's the next one.", 'ba1ea23377644394f96e4c19bbf7c03a23b22dd3757c38148b0bc98064708fc88550b46f89f77cfdf265eb35af82b4b526264bc722e85760aca40b1707082da5b5e7903540a3432a130a7b2655c855a06bb0005f5d500d4e5664ae80acb03f4f7c5dae03b8a5ed0bc60c3227212156c9'),
    (b'Somebody has to start. Somebody has to step forward and do what is right, because it is right.', '879659d6efc8fdb116110068266da5068c6335d51152f041d47f1f03d6a35230c7eb10309bf739b3780b9a59ae367813f998e1e6d84db78a2d06517529234d2deeb09cc9ca82dcc1a5ffd1344c3e0ed9d95d7714444476ec7ed5f9237af517409df4fbf974fbc8e00cd140878cb79028'),
    (b"Accept the pain, but don't accept that you deserved it.", '7e3320f30329c8211ee6bf3fe6afb06c80e575c597fabf9926cabfa5b2a202d0cd294865326e1289b01343c1537aefe251974dfda261c245acc75daa90b0148fc90c4288cb89eca1f442630927921778'),
    (b"There's always another secret.", 'e6a5848b0de3b162f98e23e56972bff6de0a7305c41ce921ec56c19af4921ed367ecc25305544a5c722640dbfdf27105')
]

#this function is used to divide the list of lists of possible chunks of keys into n lists of equal length
#this facilates the parallel processing of the chunks,because i can give a list to every core of the cpu
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
    print("len: ",len(listTmp1))
    for elem in listTmp1:
        listFinal.append(elem)
        for elem1 in list_of_lists:
            listFinal.append(elem1)
        listsFinal.append(listFinal)
        listFinal = []

    return listsFinal

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

def decrypt_message(key, ciphertext,iv):
    #ciphertext = bytes.fromhex(ciphertext)
    # Extract the IV from the beginning of the ciphertext
    #iv = ciphertext[:AES.block_size]

    # Create AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext

    decrypted_data = cipher.decrypt(ciphertext[AES.block_size:])
    
    # Unpad the decrypted data
    #unpadded_data = unpad(decrypted_data, AES.block_size)
    
    # Return the unpadded data
    return decrypted_data

#this function is used to generate all the possible combinations of the chunks of keys, and once teh msg is decrypted it checks if it is the right one
#if it is the right one it prints the key
def generate_combinations_parallel(list_of_lists, index, current_combination, padMsg9,cyphertext,iv,counter):

    if index == len(list_of_lists):
        msg = decrypt_message(current_combination, cyphertext,iv)
        counter += 1
        #if counter % 1000000 == 0:
            #print(counter)
        if msg == padMsg9: # Set the stop event to signal other processes to stop
            print(current_combination)
        return counter

    for chunk in list_of_lists[index]:
        new_combination = current_combination + chunk
        counter = generate_combinations_parallel(list_of_lists, index + 1, new_combination, padMsg9, cyphertext,iv,counter)
    return counter

#this function prepare the list of lists of possible chunks of keys to be processed by the parallel function
#once it is ready it starts the parallel processing
def generate_combinations1(list_of_lists,padMsg9,cyphertext):
    output = multiprocessing.Queue()
    stop_event = multiprocessing.Event()  # Event to signal stopping
    processes = []
    cyphertext = bytes.fromhex(cyphertext)
    iv = cyphertext[:AES.block_size]
    listTmp = []
    listTmp1 = []
    for i in range(len(list_of_lists)):
        for comb in list_of_lists[i]:
            listTmp.append(bytes.fromhex(bits_to_hex(comb)))
        listTmp1.append(listTmp)
        listTmp = []
    n = len(listTmp1[0]) // 6
    listsToElaborate = generate_multiple_lists(listTmp1,n)
    print("lenlistsToElaborate: ",len(listsToElaborate))
    # Start a separate process for each chunk in the first list
    #for chunk in list_of_lists[0]:
        #process = multiprocessing.Process(target=generate_combinations_parallel, args=(list_of_lists, 1, chunk, padMsg9,cyphertext,iv,output, stop_event))
        #process.start()
        #processes.append(process)
    #for list in listsToElaborate:
        #process = multiprocessing.Process(target=generate_combinations_parallel, args=(list, 0, b'', padMsg9,cyphertext,iv,output, stop_event,0))
        #process.start()
        #processes.append(process)
        
    #cProfile.run('generate_combinations_parallel(listsToElaborate[0], 0, b\'\', padMsg9,cyphertext,iv,0)')
    with multiprocessing.Pool() as pool:
        results = pool.starmap(generate_combinations_parallel, zip(listsToElaborate,repeat(0),repeat(b''),repeat(padMsg9),repeat(cyphertext),repeat(iv),repeat(0)))
    # Join all processes

    # Get results from the output queue
    results = []
    return results

