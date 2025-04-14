

# First find TV apps in our dataset
    # to start of with use the csv in the same folder which lists TV apps
    # then we can use androguard to find TV apps from our dataset
# Then find ACR apps in our dataset
# the sdks 
# the permission 
# native binaries per sdk per app 
# a final csv with all these results

# The final csv will have the following columns:
    # App Name
    # Package Name
    # TV App (Yes/No)
    # ACR App (Yes/No)
    # SDKs
    # Permissions
    # Native Binaries
    # Native Binaries per SDK
    # Native Binaries per App
    # signal processing code / algorithm in the native binaries
    # signal processing code / algorithm in the native binaries per SDK

import os
import sys
import re
import config
import utils
import requests

import exodus_tracker
import csv
import json
from multiprocessing import Pool
import subprocess

from androguard.misc import AnalyzeAPK

def gplay_scrape(pkg_name):
    command = ['node', 'gplay-scrape.js', pkg_name]
    
    # Run the command and capture the output
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error running the Node.js script:")
        print(result.stderr)
        return None

    # Parse the JSON output from the Node.js script
    data = json.loads(result.stdout)
    
    return data

def xref_find(application):
    xref_full_info_dict = {}
    xref_embeddings = []
    xref_app_info_dict = {}
    xref_in_app_list = []

    try:
        apk, dex, analysis = AnalyzeAPK(application)
        app_package = apk.get_package()
        perms = apk.get_permissions()
        # aosp_permissions = apk.get_aosp_permissions()
        # tp_permissions = apk.get_third_party_permissions()
        activities = apk.get_activities()
        services = apk.get_services()
        receivers = apk.get_receivers()
        is_tv = apk.is_androidtv()
        is_leanback = apk.is_leanback()
        is_wearable = apk.is_wearable()
        certificates = apk.get_certificates_v1()
        # intent_filters = apk.get_intent_filters()

        sign_result = None
        cert_info = None
        if apk.is_signed():
    # Test if signed v1 or v2 or both
            is_signed_v1 = apk.is_signed_v1()
            is_signed_v2 = apk.is_signed_v2()
            sign_result = "both" if is_signed_v1 and is_signed_v2 else "v1" if is_signed_v1 else "v2"
            print("APK is signed with: {}".format(sign_result))

        for cert in apk.get_certificates():
            cert_info = {
                'sha1': cert.sha1.hex(),
                'sha256': cert.sha256.hex(),
                'issuer': cert.issuer.human_friendly,
                'subject': cert.subject.human_friendly,
                'hash_algo': cert.hash_algo,
                'signature_algo': cert.signature_algo,
                'serial_number': cert.serial_number,
                # 'contents': cert.contents
            }
            print("Certificate Info: {}".format(cert_info))
    except Exception as e:
        print("Failed to unpack and parse the apk due to {}".format(e))
        return []

    # package paths in calls are given with
    # slashes
    app_package = app_package.replace('.', '/')

    for class_ in list(analysis.get_classes()):
        # print("Analyzing {} class '{}'".format(args.sdk, str(class_.name)))
        for method_ in list(class_.get_methods()):
            # print("\tAnalyzing the method '%s'" % (str(method_.name)))
            xrefs_to_method = method_.get_xref_from()
            for _, call, _ in xrefs_to_method:
                xref_full_info_dict = {
                    'callee_class': str(class_.name),
                    'callee_method': str(method_.name),
                    'caller_class': str(call.class_name)
                }
                xref_embeddings.append(xref_full_info_dict)
                # print("\t\tAnalyzing xref '%s'" % (str(call.class_name)))
                if app_package in str(call.class_name):
                    xref_app_info_dict = {
                        'callee_class': str(class_.name),
                        'callee_method': str(method_.name),
                        'caller_class': str(call.class_name)
                    }
                    # print("{} -- {} is called from -> {}".format(class_.name, method_.name, call.class_name))
                    xref_in_app_list.append(xref_app_info_dict)

    app_comp = {
        'activities': activities,
        'services': services,
        'receivers': receivers,
        # 'intent_filters': intent_filters
    }

    return perms, app_comp, sign_result, cert_info, is_tv, is_leanback, is_wearable, xref_embeddings, xref_in_app_list


class sdk_detection:
    def __init__(self, path, app_dir, file_hash):
        self.apk_path = path
        self.app_dir = app_dir
        self.hash = file_hash
        self.baksmali_classes = None
        self.dexdump_classes = []

    def using_exodus(self):
        tracker = exodus_tracker.Trackers(self.app_dir)
        t_res_dict = tracker.get_trackers()
        return t_res_dict


def getApkInfo(apk_path):
    get_info_command = "%s dump badging %s" % (config.AAPT_BINARY, apk_path)
    output = os.popen(get_info_command).read()
    match = re.compile("package: name='(\S+)' versionCode='(\d+)' versionName='(\S+)'").match(output)
    if not match:
        raise Exception("can't get packageinfo")

    packagename = match.group(1)
    versionCode = match.group(2)
    versionName = match.group(3)

    return packagename, versionCode, versionName


def get_apk_path(file_hash):
    #Base paths where APKs may be located
    base_path1 = "/troll/lair0/beacons/dataset/large_dataset/"
    base_path2 = "/naga/lair0/fuzzy_fitness/app_dataset/large_dataset/"

    path1 = os.path.join(base_path1, f"{file_hash}")
    path2 = os.path.join(base_path2, f"{file_hash}")
    if os.path.exists(path1):
        return path1
    elif os.path.exists(path2):
        return path2
    else:
        return None

def check_app_availability(package_name):
    print("checking availability for {}".format(package_name))
    url = f"https://play.google.com/store/apps/details?id={package_name}"
    try:
        response = requests.get(url, timeout=10)  # Added timeout for safety
        if response.status_code == 200:
            return package_name, True
    except Exception as e:
        print(f"Error checking availability for {package_name}: {e}")
    return package_name, False

def process_apk(apk_path):
    file_hash = utils.sha256(apk_path)  # Assuming you have a utility function to compute SHA256

    res_dir = '/troll/lair0/beacons/acr-sa-new'
    res_dir_2 = '/troll/lair0/beacons/acr-sa'

    if not os.path.exists(res_dir):
        os.makedirs(res_dir)
    res_dir_json = res_dir + '/' + file_hash + '.json'

    data_dir = '/troll/lair0/beacons/acr-sa-intermediate'
    out_app_dir = data_dir + '/' + file_hash

    res_dir_2_json = os.path.join(res_dir_2, file_hash + '.json')

    if os.path.exists(res_dir_json) or os.path.exists(res_dir_2_json):
        print(f"Skipping {apk_path} as it has already been processed.")
        return

    print(f"Analyzing {apk_path}")
    utils.unzip(apk_path, out_app_dir)

    apk_basic_info = {}

    try:
        packagename, versionCode, versionName = getApkInfo(apk_path)
        sdk = sdk_detection(apk_path, out_app_dir, file_hash)
        exodus_trackers = sdk.using_exodus()

        perm, app_comp, sign_result, cert_info, is_tv, is_leanback, is_wearable, xref_embeddings, xref_in_app_list = xref_find(apk_path)
        pkg, status = check_app_availability(packagename)
        if status:
            print(f"Google Play status for {packagename}: Available")
            gplay_data = gplay_scrape(packagename)

        apk_basic_info = {
            'package_name': packagename,
            'File_hash': file_hash,
            'version_Code': versionCode,
            'version_Name': versionName,
            'perms': perm,
            'app_comp': app_comp,
            'sign_result': sign_result,
            'cert_info': cert_info,
            'is_tv': is_tv,
            'is_leanback': is_leanback,
            'is_wearable': is_wearable,
            'exodus_trackers': exodus_trackers,
            'gplay_status': status,
            'gplay_data': gplay_data if status else 'Unavailable'
            # 'xref_embeddings': xref_embeddings.decode('utf-8') if isinstance(xref_embeddings, bytes) else xref_embeddings,
            # 'xref_in_app_list': xref_in_app_list.decode('utf-8') if isinstance(xref_in_app_list, bytes) else xref_in_app_list
        }

        print(apk_basic_info)

    except Exception as e:
        print(f"Failed to get APK info: {e}")

    overall_result = {
        'apk_basic_info': apk_basic_info
    }

    if not os.path.isfile(res_dir + '/' + file_hash + '.json'):
        with open(res_dir + '/' + file_hash + '.json', 'w') as fp:
            json.dump(overall_result, fp)


def get_apk_files_from_directories(directories):
    """Retrieve all APK files from a list of directories."""
    apk_files = []
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(".apk"):
                    apk_files.append(os.path.join(root, file))
    return apk_files


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <apk_path>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    process_apk(apk_path)

