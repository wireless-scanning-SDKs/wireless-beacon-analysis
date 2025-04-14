import json
import os
import csv

remove_pkg = ['androidx/core/', 'androidx/', 'com/google/android/material/', 'android/support/', 'android/support/v7/',
              'kotlinx/', 'kotlin/', 'com/google/common', 'com/google/android/', 'io/flutter/', 'com/google/zxing/',
                'com/google/android/exoplayer2', 'com/google/android/gms/location/GeofencingClient', 'com/google/android/gms/location/GeofencingRequest']

acr_pkg = ['com/instreamatic', 'com/acrcloud', 'com/yinzcam/sobek', 'com/cueaudio', 'com/redbricklane/zapr', 'ccue/'
           "com/mufin", "com/digimarc/dms", "com/signal360/sdk/core", "com/sonicnotify/sdk/core", "com/rnsignal360", "io/chirp/connect",
           "com/lisnr", "com/hound", "ai/kitt/snowboy", "com/fidzup", "com/cifrasoft", "com/fluzo/sdk", "com/moodmedia", "com/silverpush", "com/axwave", 
           "com/trillbit/datasdk", "com/intrasonics", "tv/alphonso/service",
           "io/spokestack/spokestack", "com/beatgridmedia", "com/shopkick/sdk/api", "com/shopkick/fetchers", "com/copsonic"
           ]

bt_pkg = [
    'com/yinzcam/sobek',
    'com/signal360/sdk/core',
    'com/sonicnotify/sdk/core',
    'com/rnsignal360',
    'com/cueaudio/engine',
    'com/cueaudio/live',
    'org/altbeacon/beacon',
    'com/altbeacon/beacon',
    'org/altbeacon/bluetooth',
    'com/radiusnetworks',
    'com/estimote',
    'com/gimbal/android',
    'com/kontakt/sdk/android',
    'com/cuebiq/cuebiqsdk/model/Collector',
    'com/cuebiq/cuebiqsdk/receiver/CoverageReceiver',
    'com/ad4screen/sdk',
    'com/stepleaderdigital/reveal',
    'com/wirelessregistry/observersdk',
    'com/indooratlas/android/sdk',
    'io/rover',
    'coelib/c/couluslibrary',
    'com/beaconsinspace/android/beacon/detector',
    'com/inmarket',
    'com/sense360/android',
    'com/locuslabs/sdk',
    'com/roximity/sdk',
    'com/bluecats/sdk',
    'com/sensoro/beacon/kit',
    'com/sensoro/cloud',
    'com/swirl',
    'com/placer/client/Placer',
    'com/pure/internal',
    'com/pure/sdk',
    'com/pointinside',
    'com/webgeoservices',
    'com/innoquant/moca',
    'io/proximi/proximiiolibrary',
    'com/pulseid/sdk',
    'com/ubudu/sdk',
    'io/xmode/BcnConfig',
    'io/xmode/locationsdk',
    'io/mysdk',
    'io/radar/sdk/Radar',
    'io/radar/sdk',
    'com/areametrics/areametricssdk',
    'com/areametrics/nosdkandroid',
    'com/bluekai/sdk',
    'net/crowdconnected/androidcolocator',
    'io/huq/sourcekit',
    'com/adobe/mobile/Analytics',
    'com/adobe/mobile/Config',
    'com/foursquare/pilgrim',
    'com/foursquare/pilgrimsdk/android',
    'com/dynamicyield',
    'com/sptproximitykit',
    'com/salesforce/marketingcloud',
    'com/mparticle',

    'com/leanplum',
    'com/zendrive/sdk',
    'com/swrve/sdk',
    'com/infinario/android/infinariosdk',
    'com/exponea/sdk',
    'com/sygic/aura',
    'com/safegraph',
    'com/openlocate',
    'com/kochava/base',
    'com/kochava/android/tracker',
    'com/kochavaccpa',
    'com/telescope/android',
    'io/predic/tracker',
    'sdk/predic/io',
    'com/bazaarvoice/bvandroidsdk',
    'com/redbricklane/zapr',
    'com/precisely'
]


def extract_rule_findings(data):
    package_name = data['app'].get('package', '')
    package_prefix = '/'.join(package_name.split('.')[:2])  # com/webappclouds

    rule_findings = []

    for rule in data.get('rules', []):
        rule_info = {
            'title': rule['rule'].get('title', 'N/A'),
            'name': rule['rule'].get('name', 'N/A'),
            'findings': [],                    # All findings
            'first_party_findings': [],        # First-party only
            'third_party_findings': []        # Third-party only (excluding first-party and bt beacon)
            # 'bt_package_findings': []          # Bluetooth-related packages
        }

        # Process all findings
        for finding in rule.get('findings', []):
            finding_info = {
                'id': finding.get('id', 'N/A'),
                'call_by': finding.get('call_by', 'N/A')
            }

            if any(finding_info['call_by'].startswith(pkg) for pkg in remove_pkg):
                continue  # Skip excluded packages

            rule_info['findings'].append(finding_info)

            if finding_info['call_by'].startswith(package_prefix):
                rule_info['first_party_findings'].append(finding_info)

            # elif any(finding_info['call_by'].startswith(pkg) for pkg in bt_pkg):
            #     rule_info['bt_package_findings'].append(finding_info)

        # Third-party = findings not in first-party and not Bluetooth
        for finding in rule_info['findings']:
            if (
                finding not in rule_info['first_party_findings'] 
                # and finding not in rule_info['bt_package_findings']
            ):
                rule_info['third_party_findings'].append(finding)

        rule_findings.append(rule_info)

    return rule_findings


def read_json_files_from_directory(directory):
    json_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('report.json'):
                print(file)
                json_files.append(os.path.join(root, file))
    return json_files

def process_files_and_write_to_csv(directory, output_csv):
    json_files = read_json_files_from_directory(directory)
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['file_hash', 'package_name', 'rule_title', 'name', 'finding_id', 'call_by', 'finding_type']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for json_file in json_files:
            file_hash = os.path.basename(os.path.dirname(json_file))
            with open(json_file, 'r') as file:
                data = json.load(file)

            package_name = data['app'].get('package', '')
            rule_findings = extract_rule_findings(data)

            for rule in rule_findings:
                for finding in rule['findings']:
                    writer.writerow({
                        'file_hash': file_hash,
                        'package_name': package_name,
                        'rule_title': rule['title'],
                        'name': rule['name'],
                        'finding_id': finding['id'],
                        'call_by': finding['call_by'],
                        'finding_type': 'all_findings'
                    })
                for finding in rule['first_party_findings']:
                    writer.writerow({
                        'file_hash': file_hash,
                        'package_name': package_name,
                        'rule_title': rule['title'],
                        'name': rule['name'],
                        'finding_id': finding['id'],
                        'call_by': finding['call_by'],
                        'finding_type': 'first_party_findings'
                    })
                for finding in rule['third_party_findings']:
                    writer.writerow({
                        'file_hash': file_hash,
                        'package_name': package_name,
                        'rule_title': rule['title'],
                        'name': rule['name'],
                        'finding_id': finding['id'],
                        'call_by': finding['call_by'],
                        'finding_type': 'third_party_findings'
                    })
                # for finding in rule['bt_package_findings']:
                #     writer.writerow({
                #         'file_hash': file_hash,
                #         'package_name': package_name,
                #         'rule_title': rule['title'],
                #         'name': rule['name'],
                #         'finding_id': finding['id'],
                #         'call_by': finding['call_by'],
                #         'finding_type': 'bt_package_findings'
                #     })

# Path to the directory containing the JSON files
#json_directory_path = '/data/acr/perms_api_mapping_results'
# json_directory_path = '/data/beacon/geofence'
# output_csv_path = 'geofence.csv'

json_directory_path = '/data/localhost/androcfg_output/'
output_csv_path = 'localhost.csv'

# Process the files and write the results to the CSV file
process_files_and_write_to_csv(json_directory_path, output_csv_path)
