import os
import networkx as nx
import pandas as pd
import json
import sys
from csv import DictWriter

# Define the Bluetooth-related package mappings
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

def load_graph(dot_file_path):
    print(f"Loading graph from {dot_file_path}...")
    graph = nx.drawing.nx_pydot.read_dot(dot_file_path)
    print("Graph loaded.")
    return graph

def load_system_apis(json_file_path):
    print(f"Loading system APIs from {json_file_path}...")
    with open(json_file_path, 'r') as f:
        system_apis = json.load(f)
    api_dict = {}
    for entry in system_apis:
        for api in entry['or_predicates']:
            normalized_api = normalize_api_string(api)
            api_dict[normalized_api] = entry['name']
    print("System APIs loaded.")
    return api_dict

def normalize_api_string(api):
    api = api.replace('<init>', 'init')
    api = api.replace('$', '/')
    if ';->' in api:
        parts = api.split(';->')
        class_part = parts[0]
        method_part = parts[1].split('(')[0]
        return class_part + '/' + method_part
    if '(' in api:
        return api.split('(')[0]
    return api

def extract_package_name(full_class_name):
    parts = full_class_name.split('/')
    if len(parts) > 1:
        return '/'.join(parts[:2])
    return full_class_name

def find_sdk(package_name, bt_pkg):
    for sdk, pkgs in bt_pkg.items():
        if any(package_name.startswith(pkg) for pkg in pkgs):
            return sdk
    return package_name.split('/')[1] if '/' in package_name else package_name  # Return the second part of the package name as SDK

def is_host_package(package_name, host_app_package):
    host_package_path = 'L' + host_app_package.replace('.', '/')
    if package_name in host_package_path:
        print(package_name, host_package_path)
    return package_name in host_package_path

def find_interactions(graph, host_app_package, bt_pkg, system_apis, file_hash, dot_file_name, writer):
    api_dict = system_apis
    for edge in graph.edges:
        caller, callee = edge[0], edge[1]
        caller_pkg = extract_package_name(caller)
        callee_pkg = extract_package_name(callee)
        
        normalized_callee = normalize_api_string(callee)
        interaction_type = "Intra-library"
        system_api_name = None
        
        if normalized_callee in api_dict:
            interaction_type = "System API"
            system_api_name = api_dict[normalized_callee]
        elif caller_pkg != callee_pkg:
            if is_host_package(caller_pkg, host_app_package) or is_host_package(callee_pkg, host_app_package):
                interaction_type = "Host to third-party"
            else:
                interaction_type = "Cross-library"
        elif is_host_package(caller_pkg, host_app_package) and is_host_package(callee_pkg, host_app_package):
            interaction_type = "Host to host"
        
        caller_sdk = find_sdk(caller_pkg, bt_pkg)
        callee_sdk = find_sdk(callee_pkg, bt_pkg)
        
        row = {
            "Caller": caller,
            "Callee": callee,
            "Type": interaction_type,
            "Caller_sdk": caller_sdk if caller_sdk else "None",
            "Callee_sdk": callee_sdk if callee_sdk else "None",
            "System API Interaction": system_api_name if system_api_name else "None",
            "file_hash": file_hash,
            "package_name": host_app_package,
            "dot_file_name": dot_file_name
        }
        writer.writerow(row)

def process_directory(directory_path, system_api_json_path, output_file_path):
    with open(output_file_path, mode='w', newline='') as file:
        fieldnames = ["Caller", "Callee", "Type", "Caller_sdk", "Callee_sdk", "System API Interaction", "file_hash", "package_name", "dot_file_name"]
        writer = DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        
        for file_hash in os.listdir(directory_path):
            file_hash_path = os.path.join(directory_path, file_hash)
            if os.path.isdir(file_hash_path):
                cfg_path = os.path.join(file_hash_path, 'cfg')
                report_path = os.path.join(file_hash_path, 'report.json')
                
                # Load host package name from report.json
                try:
                    with open(report_path, 'r') as report_file:
                        report_data = json.load(report_file)
                        host_app_package = report_data['app']['package']
                except Exception as e:
                    print(f"Error reading {report_path}: {e}")
                    continue
                
                # Process each DOT file in the cfg directory
                for dot_file_name in os.listdir(cfg_path):
                    dot_file_path = os.path.join(cfg_path, dot_file_name)
                    if not dot_file_name.endswith('.png'):
                        try:
                            graph = load_graph(dot_file_path)
                            system_apis = load_system_apis(system_api_json_path)
                            find_interactions(graph, host_app_package, bt_pkg, system_apis, file_hash, dot_file_name, writer)
                        except Exception as e:
                            print(f"Error processing {dot_file_path}: {e}")

def generate_report(interaction_df, output_file_path):
    # Summary statistics
    total_interactions = len(interaction_df)
    interaction_summary = interaction_df['Type'].value_counts().to_dict()
    
    # Detailed report
    report = f"Total Interactions: {total_interactions}\n\n"
    report += "Interaction Summary:\n"
    for interaction_type, count in interaction_summary.items():
        report += f"  {interaction_type}: {count}\n"
    
    report += "\nSDK Interaction Summary:\n"
    caller_sdk_summary = interaction_df['Caller_sdk'].value_counts().to_dict()
    callee_sdk_summary = interaction_df['Callee_sdk'].value_counts().to_dict()
    
    report += "Caller SDKs:\n"
    for sdk, count in caller_sdk_summary.items():
        report += f"  {sdk}: {count}\n"
    
    report += "\nCallee SDKs:\n"
    for sdk, count in callee_sdk_summary.items():
        report += f"  {sdk}: {count}\n"
    
    # Save the detailed interaction DataFrame to CSV
    interaction_df.to_csv(output_file_path, index=False)
    
    # Print the summary report
    print(report)


def main(directory_path, system_api_json_path, output_file_path):
    process_directory(directory_path, system_api_json_path, output_file_path)
    # generate_report(combined_df, output_file_path)
    # # combined_df.to_csv(output_file_path, index=False)
    # print("Processing complete. Output saved to:", output_file_path)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py <directory_path> <system_api_json_path> <output_file_path>")
    
    directory_path = sys.argv[1]
    system_api_json_path = sys.argv[2]
    output_file_path = sys.argv[3]
    main(directory_path, system_api_json_path, output_file_path)
