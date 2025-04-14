import os
import json
import re
import pandas as pd

# Define the list of Bluetooth and beacon SDK packages
bt_pkg = {
    'yinzcam': ['com/yinzcam/sobek'],
    'signal360': ['com/signal360/sdk/core', 'com/sonicnotify/sdk/core', 'com/rnsignal360'],
    'cueAudio': ['com/cueaudio/engine', 'com/cueaudio/live'], 
    'Altbeacon': ['org/altbeacon/beacon','com/altbeacon/beacon', 'org/altbeacon/bluetooth'],
    'Radius Networks': ['com/radiusnetworks'],
    'Estimote': ['com/estimote'],
    'Gimbal': ['com/gimbal/android'],
    'Kontakt': ['com/kontakt/sdk/android'],
    'Cuebiq': ['com/cuebiq/cuebiqsdk/model/Collector', 'com/cuebiq/cuebiqsdk/receiver/CoverageReceiver'],
    'ad4screen': ['com/ad4screen/sdk'],
    'reveal': ['com/stepleaderdigital/reveal'],
    'SignalFrame': ['com/wirelessregistry/observersdk'],
    'indooratlas': ['com/indooratlas/android/sdk'],
    'rover': ['io/rover'],
    'coelib': ['coelib/c/couluslibrary'],
    'BeaconsInSpace': ['com/beaconsinspace/android/beacon/detector'],
    'inmarket': ['com/inmarket'],
    'sense360': ['com/sense360/android'],
    'locuslabs': ['com/locuslabs/sdk'],
    'roximity': ['com/roximity/sdk'],
    'bluecats': ['com/bluecats/sdk'],
    'sensoro': ['com/sensoro/beacon/kit', 'com/sensoro/cloud'], 
    'swirl': ['com/swirl'],
    'placer': ['com/placer/client/Placer'],
    'Unacast Pure': ['com/pure/internal', 'com/pure/sdk'],
    'Point Inside': ['com/pointinside'],
    'Woosmap SDK': ['com/webgeoservices'],
    'MOCA': ['com/innoquant/moca'],
    'Proximi.io': ['io/proximi/proximiiolibrary'],
    'pulseid': ['com/pulseid/sdk'],
    'ubudu': ['com/ubudu/sdk'],
    'X-Mode': ['io/xmode/BcnConfig', 'io/xmode/locationsdk', 'io/mysdk'],
    'Radar': ['io/radar/sdk/Radar'],
    'areametrics': ['com/areametrics/areametricssdk', 'com/areametrics/nosdkandroid'],
    'bluekai': ['com/bluekai/sdk'],
    'Colocater': ['net/crowdconnected/androidcolocator'],
    'Huq Sourcekit': ['io/huq/sourcekit'],
    'Demdex': ['com/adobe/mobile/Analytics', 'com/adobe/mobile/Config'],
    'Pilgrim by Foursquare': ['com/foursquare/pilgrim', 'com/foursquare/pilgrimsdk/android'],
    'Dynamic Yield': ['com/dynamicyield'],
    'Singlespot': ['com/sptproximitykit'],
    'Salesforce Marketing Cloud': ['com/salesforce/marketingcloud'],
    'mParticle': ['com/mparticle'],
    'LeanPlum': ['com/leanplum'],
    'Zendrive': ['com/zendrive/sdk'],
    'Swrve': ['com/swrve/sdk'],
    'Exponea': ['com/infinario/android/infinariosdk', 'com/exponea/sdk', 'com/sygic/aura'],
    'OpenLocate (Safegraph)': ['com/safegraph', 'com/openlocate'],
    'kochava': ['com/kochava/base', 'com/kochava/android/tracker', 'com/kochavaccpa'],
    'PredicIO': ['com/telescope/android', 'io/predic/tracker', 'sdk/predic/io'],
    'bazaarvoice': ['com/bazaarvoice/bvandroidsdk'],
    'zapr': ['com/redbricklane/zapr'],
    'precisely': ['com/precisely']
}

# Permissions related to location and Bluetooth
location_and_bt_permissions = [
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.BLUETOOTH',
    'android.permission.BLUETOOTH_ADMIN',
    'android.permission.BLUETOOTH_SCAN',
    'android.permission.BLUETOOTH_CONNECT',
    'android.permission.BLUETOOTH_ADVERTISE'
]


# Directory containing the JSON files
json_dir = '/data/beacon/consent_rationale/results-new'

sdk_list = '/home/aniketh/devel/src/ble-beacon/beacon-finder/analysis/bt_beacon_sdk_apps.csv'
df = pd.read_csv(sdk_list)
df['file_hash'] = df['file_hash'].str.upper()  # Ensure consistency in case formatting

# Function to extract the top and second level domains from a package name
def extract_top_two_levels(package_name):
    parts = package_name.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[:2])
    return package_name

# Function to determine if the call is third-party
def is_third_party(caller_pkg, callee_pkg, app_pkg):
    caller_domain = extract_top_two_levels(caller_pkg)
    callee_domain = extract_top_two_levels(callee_pkg)
    app_domain = extract_top_two_levels(app_pkg)
    return caller_domain != app_domain and callee_domain != app_domain and caller_domain != callee_domain

# Function to determine if the call is first-party
def is_first_party(caller_pkg, app_pkg):
    caller_domain = extract_top_two_levels(caller_pkg)
    app_domain = extract_top_two_levels(app_pkg)
    return caller_domain == app_domain

# Function to determine if the call is made by a Bluetooth and beacon SDK package
def is_bt_pkg(caller_pkg, bt_pkg):
    for pkgs in bt_pkg.values():
        for pkg in pkgs:
            if pkg in caller_pkg:
                return True
    return False

# Function to parse JSON files and extract relevant information
def parse_json_files(directory, bt_pkg, df):
    results = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    apk = data.get('apk')
                    file_hash = os.path.splitext(apk)[0].upper()  # Get the file hash without extension

                    # Find the corresponding package name from the dataframe
                    package_name_row = df[df['file_hash'] == file_hash]
                    if not package_name_row.empty:
                        package_name = package_name_row.iloc[0]['package_name']
                    else:
                        package_name = None

                    matches = data.get('matches', {})
                    should_show_matches = matches.get('shouldShowRequestPermissionRationale', {})
                    for file_path, entries in should_show_matches.items():
                        for entry in entries:
                            code = entry['code']
                            params = entry['params']
                            caller_pkg = file_path.replace('/', '.')  # Convert path to package format
                            # for sdk_name, pkgs in bt_pkg.items():
                            #     for pkg in pkgs:
                            #         if pkg in file_path:
                            for param in params:
                                callee_pkg = param.replace('/', '.')
                                third_party = is_third_party(caller_pkg, callee_pkg, package_name)
                                first_party = is_first_party(caller_pkg, package_name)
                                bt_pkg_flag = is_bt_pkg(caller_pkg, bt_pkg)
                                results.append({
                                    'apk': apk,
                                    'file': file_path,
                                    'package_name': package_name,
                                    'line_number': entry['line_number'],
                                    'code': code,
                                    'params': params,
                                    'permission': param,
                                    # 'sdk_name': sdk_name,
                                    'pattern': 'shouldShowRequestPermissionRationale',
                                    'third_party': third_party,
                                    'first_party': first_party,
                                    'bt_pkg': bt_pkg_flag
                                })
    return results

# Parse the JSON files and extract relevant information
results = parse_json_files(json_dir, bt_pkg, df)

# Write the results to a new JSON file
output_file = 'parsed_results_with_package_name_and_party_info_no_bt.json'
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=4)

print(f"Results written to {output_file}")