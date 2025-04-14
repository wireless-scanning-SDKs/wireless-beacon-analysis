import os
import sys
import json
import logging
import argparse
import pandas as pd
from androguard.misc import AnalyzeAPK
from multiprocessing import Process, JoinableQueue, Lock, active_children

# Constants
NUMBER_OF_PROCESSES = 40
STATUS_LOGGING = 'logging'
STATUS_ERROR = 'error'
STATUS_DONE = 'done'

dataset = '/home/aniketh/devel/src/ble-beacon/beacon-finder/analysis/bt_beacon_sdk_apps.csv'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_apk_path(file_hash):
    base_path1 = "/troll/lair0/beacons/dataset/large_dataset/"
    base_path2 = "/naga/lair0/fuzzy_fitness/app_dataset/large_dataset/"
    path1 = os.path.join(base_path1, f"{file_hash}.apk")
    path2 = os.path.join(base_path2, f"{file_hash}.apk")
    if os.path.exists(path1):
        return path1
    elif os.path.exists(path2):
        return path2
    else:
        return None

def get_version(apk_path):
    try:
        app, _, _ = AnalyzeAPK(apk_path)
        min_sdk = app.get_min_sdk_version()
        target_sdk = app.get_target_sdk_version()
        max_sdk = app.get_max_sdk_version()
        effective_target_sdk = app.get_effective_target_sdk_version()
        return min_sdk, target_sdk, max_sdk, effective_target_sdk
    except Exception as e:
        logging.error(f"Error processing {apk_path}: {e}")
        return None, None, None, None

def map_sdk_code_to_version():
    return {
        "Android 15": [35],
        "Android 14": [34],
        "Android 13": [33],
        "Android 12": [32, 31],
        "Android 11": [30],
        "Android 10": [29],
        "Android 9": [28],
        "Android 8.1": [27],
        "Android 8.0": [26],
        "Android 7.1": [25],
        "Android 7.0": [24],
        "Android 6.0": [23],
        "Android 5.1": [22],
        "Android 5.0": [21]
    }

def get_android_version(sdk_version, version_dict):
    if sdk_version is None:
        return None
    try:
        sdk_version = int(sdk_version)
        for version, sdk_codes in version_dict.items():
            if sdk_version in sdk_codes:
                return version
        return f"Unknown (API {sdk_version})"
    except ValueError:
        return None

def process_apk(apk_hash, send_queue, receive_queue, lock):
    apk_path = get_apk_path(apk_hash)
    version_dict = map_sdk_code_to_version()
    if apk_path:
        min_sdk, target_sdk, max_sdk, effective_target_sdk = get_version(apk_path)
        android_version = get_android_version(target_sdk, version_dict)
        result = {
            'file_hash': apk_hash,
            'min_sdk': min_sdk,
            'target_sdk': target_sdk,
            'max_sdk': max_sdk,
            'effective_target_sdk': effective_target_sdk,
            'android_version': android_version
        }
        with lock:
            with open('sdk_versions.csv', 'a') as f:
                pd.DataFrame([result]).to_csv(f, header=False, index=False)
        receive_queue.put((apk_hash, STATUS_DONE, result))
    else:
        receive_queue.put((apk_hash, STATUS_ERROR, f"APK not found for hash {apk_hash}"))
    send_queue.task_done()

def read_dataset():
    return pd.read_csv(dataset)

def main():
    df = read_dataset()
    apk_hashes = df['file_hash'].tolist()
    total_apks = len(apk_hashes)

    process_send_queue = JoinableQueue()
    process_receive_queue = JoinableQueue()
    lock = Lock()

    # Write the header to the CSV file
    with open('sdk_versions.csv', 'w') as f:
        header = ['file_hash', 'min_sdk', 'target_sdk', 'max_sdk', 'effective_target_sdk', 'android_version']
        pd.DataFrame(columns=header).to_csv(f, header=True, index=False)

    processes = []
    for i in range(NUMBER_OF_PROCESSES):
        process = Process(target=worker, args=(process_send_queue, process_receive_queue, lock))
        process.start()
        processes.append(process)

    for apk_hash in apk_hashes:
        process_send_queue.put(apk_hash)

    completed_apk_count = 0
    while completed_apk_count < total_apks:
        apk_hash, status, result = process_receive_queue.get()
        process_receive_queue.task_done()
        completed_apk_count += 1
        if status == STATUS_DONE:
            logging.info(f"Processed: {result}")
        else:
            logging.error(result)
        logging.info(f"Progress: {completed_apk_count}/{total_apks} processed.")

    for process in processes:
        process_send_queue.put('STOP')

    process_send_queue.join()
    process_receive_queue.join()

def worker(send_queue, receive_queue, lock):
    while True:
        apk_hash = send_queue.get()
        if apk_hash == 'STOP':
            send_queue.task_done()
            break
        process_apk(apk_hash, send_queue, receive_queue, lock)

if __name__ == '__main__':
    main()
