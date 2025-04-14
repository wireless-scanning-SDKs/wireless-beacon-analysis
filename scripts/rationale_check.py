import os
import re
import subprocess
import json
import pandas as pd
from xml.etree import ElementTree as ET

BASE_PATHS = [
    "/troll/lair0/beacons/dataset/large_dataset/",
    "/naga/lair0/fuzzy_fitness/app_dataset/large_dataset/"
]

jadx_path = '/home/aniketh/devel/src/ble-beacon/AndroCFG/bin/bin/jadx'
output_dir = '/data/beacon/consent_rationale/decompiled_output'
result_dir = '/data/beacon/consent_rationale/results-new'
search_patterns = {
    'shouldShowRequestPermissionRationale': r'\bshouldShowRequestPermissionRationale\s*\((.*?)\)',
    'requestPermissions': r'\brequestPermissions\s*\((.*?)\)',
    'checkSelfPermission': r'\bcheckSelfPermission\s*\((.*?)\)',
    'onRequestPermissionsResult': r'\bonRequestPermissionsResult\s*\((.*?)\)',
}

def get_apk_path(file_hash):
    for base_path in BASE_PATHS:
        apk_path = os.path.join(base_path, f"{file_hash}.apk")
        if os.path.exists(apk_path):
            return apk_path
    return None

def decompile_apk(apk_path, output_dir):
    output_subdir = os.path.join(output_dir, os.path.splitext(os.path.basename(apk_path))[0])
    if os.path.exists(output_subdir) and os.listdir(output_subdir):
        print("Directory exists and is not empty, assume decompilation is already done")
        return output_subdir
    os.makedirs(output_subdir, exist_ok=True)
    cmd = [jadx_path, apk_path, '-d', output_subdir, '-j', '10', '--deobf', '-r']
    subprocess.run(cmd, check=True)
    return output_subdir

# def search_in_files(directory, patterns):
#     print(f"Searching in {directory} for {patterns}")
#     result = {}
#     for pattern_name, pattern in patterns.items():
#         regex = re.compile(pattern)
#         for root, dirs, files in os.walk(directory):
#             for file in files:
#                 if file.endswith(".java"):
#                     file_path = os.path.join(root, file)
#                     with open(file_path, 'r', encoding='utf-8') as f:
#                         for i, line in enumerate(f):
#                             match = regex.search(line)
#                             if match:
#                                 params = match.group(1)
#                                 entry = {
#                                     'line_number': i + 1,
#                                     'code': line.strip(),
#                                     'params': [p.strip() for p in params.split(',')]
#                                 }
#                                 relative_file_path = file_path.replace(directory + '/sources/', '')
#                                 if pattern_name not in result:
#                                     result[pattern_name] = {}
#                                 if relative_file_path not in result[pattern_name]:
#                                     result[pattern_name][relative_file_path] = []
#                                 result[pattern_name][relative_file_path].append(entry)
#     return result


def search_in_files(directory, patterns):
    print(f"Searching in {directory} for {patterns}")
    result = {}

    exclude_dirs = [
        'android', 'androidx', 'kotlin', 'kotlinx', 'okhttp3', 'okio',
        'retrofit2', 'com/squareup', 'com/google', 'com/facebook',
        'com/jakewharton', 'com/airbnb', 'com/bumptech', 'com/spotify'
    ]
    exclude_dirs_option = ' '.join([f'--exclude-dir={d}' for d in exclude_dirs])

    for pattern_name, pattern in patterns.items():
        grep_cmd = f"grep -r --include='*.java' {exclude_dirs_option} -n -E '{pattern}' {directory}"
        try:
            grep_output = subprocess.check_output(grep_cmd, shell=True, text=True)
            for line in grep_output.splitlines():
                file_path, line_number, code = line.split(':', 2)
                params = re.search(pattern, code).group(1)
                entry = {
                    'line_number': int(line_number),
                    'code': code.strip(),
                    'params': [p.strip() for p in params.split(',')]
                }
                relative_file_path = file_path.replace(directory + '/sources/', '')
                if pattern_name not in result:
                    result[pattern_name] = {}
                if relative_file_path not in result[pattern_name]:
                    result[pattern_name][relative_file_path] = []
                result[pattern_name][relative_file_path].append(entry)
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                print(f"No matches found for pattern {pattern_name}")
            else:
                print(f"grep failed for pattern {pattern_name}: {e}")

    return result

def process_apk(file_hash):
    apk_path = get_apk_path(file_hash)
    if apk_path:
        try:
            print(f"Analyzing {apk_path}")
            decompiled_dir = decompile_apk(apk_path, output_dir)
            matches = search_in_files(decompiled_dir, search_patterns)

            result = {
                'apk': os.path.basename(apk_path),
                'matches': matches
            }
            json_output_path = os.path.join(result_dir, f"{os.path.splitext(os.path.basename(apk_path))[0]}.json")
            print(json_output_path)
            with open(json_output_path, 'w', encoding='utf-8') as json_file:
                json.dump(result, json_file, indent=4)
        except Exception as e:
            print(f"Error processing {apk_path}: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_hash>")
        sys.exit(1)

    file_hash = sys.argv[1]
    process_apk(file_hash)
