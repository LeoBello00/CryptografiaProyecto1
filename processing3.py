import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Manager

def generate_combinations_parallel(args):
    list_of_lists, index, current_combination, output, stop_event = args
    if stop_event.is_set():
        return

    if index == len(list_of_lists):
        output.put(current_combination)
        return

    for chunk in list_of_lists[index]:
        new_combination = current_combination + chunk
        generate_combinations_parallel((list_of_lists, index + 1, new_combination, output, stop_event))

def generate_combinations1(args):
    list_of_lists, index, current_combination, output, stop_event = args
    processes = []
    
    # Start a separate process for each chunk in the first list
    for chunk in list_of_lists[1]:
        process = multiprocessing.Process(target=generate_combinations_parallel, args=(list_of_lists, 2, chunk,output, stop_event))
        process.start()
        processes.append(process)

    # Join all processes
    for process in processes:
        process.join()

def generate_combinations(list_of_lists):
    manager = Manager()
    output = manager.Queue()
    stop_event = manager.Event()  # Event to signal stopping
    executor = ProcessPoolExecutor(max_workers=multiprocessing.cpu_count())

    futures = []
    for chunk in list_of_lists[0]:
        future = executor.submit(generate_combinations_parallel, (list_of_lists, 1, chunk, output, stop_event))
        futures.append(future)

    # Wait for all futures to complete
    for future in futures:
        future.result()

    # Get results from the output queue
    results = []
    while not output.empty():
        result = output.get()
        results.append(result)

    return results