import subprocess
import os
import pandas as pd
import concurrent.futures

def get_apk_path(file_hash):
    # Base paths where APKs may be located
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

def process_apk(file_hash):
    apk_path = get_apk_path(file_hash)
    if apk_path:
        print(f"Analyzing {apk_path}")
        # Replace the filepath in the command below with the apk_path
        command = f"python3 AndroCFG.py -a {apk_path} -f raw"
        subprocess.run(command, shell=True)

if __name__ == "__main__":
    df = pd.read_csv('/home/aniketh/devel/src/ble-beacon/beacon_dataset.csv')
    # df = pd.read_csv('/home/aniketh/devel/src/ble-beacon/beacon-finder/analysis/open-ended-perm-list.csv')
    # df = pd.read_csv('/home/aniketh/devel/src/ble-beacon/beacon-finder/analysis/missing_entries.csv')
    # Convert the DataFrame to a list of file hashes for easier processing with multiprocessing
    file_hashes = df['file_hash'].tolist()
    
    # Number of processes to use; you can adjust this based on your system's capabilities
    num_processes = 29

    with concurrent.futures.ProcessPoolExecutor(max_workers=num_processes) as executor:
        # Use the executor to map the process_apk function to each file hash
        executor.map(process_apk, file_hashes)
