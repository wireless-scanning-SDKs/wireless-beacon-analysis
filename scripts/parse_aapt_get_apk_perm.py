import subprocess
import re
import sys
import pandas as pd
import os

def parse_aapt_output(aapt_output):
    # Define the permissions of interest
    permissions_of_interest = [
        'android.permission.BLUETOOTH',
        'android.permission.BLUETOOTH_ADMIN',
        'android.permission.BLUETOOTH_CONNECT',
        'android.permission.BLUETOOTH_SCAN',
        'android.permission.BLUETOOTH_ADVERTISE',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.ACCESS_BACKGROUND_LOCATION',
        'android.permission.RECORD_AUDIO',
        'android.permission.CHANGE_WIFI_STATE',
        'android.permission.ACCESS_WIFI_STATE',
        'android.permission.READ_EXTERNAL_STORAGE'
    ]

    # Use regex to find all permissions in the aapt output
    found_permissions = re.findall(r"uses-permission: name='([^']+)'", aapt_output)

    # Initialize a dictionary to store the presence of each permission
    permission_results = {perm.split('.')[-1].lower(): 'false' for perm in permissions_of_interest}

    # Check if each permission of interest is present
    for perm in permissions_of_interest:
        if perm in found_permissions:
            permission_results[perm.split('.')[-1].lower()] = 'true'

    return permission_results

def process_apk(apk_path):
    # Run the aapt command to dump permissions
    # file_name = os.path.basename(apk_path)
    # app_name = file_name.split('-')[0]
    try:
        aapt_output = subprocess.check_output(['aapt', 'dump', 'badging', apk_path], universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running aapt on {apk_path}: {e}")
        return None

    # Parse the output to get permission statuses
    permissions = parse_aapt_output(aapt_output)

    # Add the APK name to the results
    permissions['package_name'] = re.search(r"package: name='([^']+)'", aapt_output).group(1)

    return permissions

def main(directory_path):
    # List to hold all the results
    all_permissions = []

    # Process each APK file in the directory
    for file in os.listdir(directory_path):
        if file.endswith('.apk'):
            print(f"Processing {file}...")
            apk_path = os.path.join(directory_path, file)
            permissions = process_apk(apk_path)
            print("processing file {} with permissions {}".format(file, permissions))
            if permissions:
                all_permissions.append(permissions)

    # Create a DataFrame with the results
    df = pd.DataFrame(all_permissions, columns=[
        'package_name', 'bluetooth', 'bluetooth_admin', 'bluetooth_connect', 
        'bluetooth_scan', 'bluetooth_advertise', 'access_fine_location', 
        'access_coarse_location', 'access_background_location', 
        'record_audio', 'change_wifi_state', 'access_wifi_state', 'read_external_storage'
    ])

    df.to_csv('bt_app_latest_perm_data_9.csv', index=False)
    print(df)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <directory_with_apks>")
        sys.exit(1)

    directory_path = sys.argv[1]
    main(directory_path)
