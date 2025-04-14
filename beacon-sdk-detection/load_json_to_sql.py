import json
import os
import psycopg2
from multiprocessing import Pool, cpu_count

def flatten_json(json_data):
    apk_basic_info = json_data.get('apk_basic_info', {})
    if not isinstance(apk_basic_info, dict):
        apk_basic_info = {}

    exodus_trackers = apk_basic_info.get('exodus_trackers', {})
    if not isinstance(exodus_trackers, dict):
        exodus_trackers = {}

    gplay_data = apk_basic_info.get('gplay_data', {})
    if not isinstance(gplay_data, dict):
        gplay_data = {}

    cert_info = apk_basic_info.get('cert_info', {})
    if isinstance(cert_info, dict):
        cert_sha1 = cert_info.get('sha1', '')
        cert_sha256 = cert_info.get('sha256', '')
        cert_issuer = cert_info.get('issuer', '')
        cert_subject = cert_info.get('subject', '')
        hash_algo = cert_info.get('hash_algo', '')
        signature_algo = cert_info.get('signature_algo', '')
        serial_number = cert_info.get('serial_number', '')
    else:
        cert_sha1 = ''
        cert_sha256 = ''
        cert_issuer = ''
        cert_subject = ''
        hash_algo = ''
        signature_algo = ''
        serial_number = ''

    return {
        "file_hash": apk_basic_info.get("File_hash"),
        "package_name": apk_basic_info.get("package_name"),
        "version_code": apk_basic_info.get("version_Code"),
        "version_name": apk_basic_info.get("version_Name"),
        "perms": apk_basic_info.get("perms", []),
        "activities": apk_basic_info.get('app_comp', {}).get('activities', []),
        "services": apk_basic_info.get('app_comp', {}).get('services', []),
        "receivers": apk_basic_info.get('app_comp', {}).get('receivers', []),
        "sign_result": apk_basic_info.get("sign_result", ''),
        "cert_sha1": cert_sha1,
        "cert_sha256": cert_sha256,
        "cert_issuer": cert_issuer,
        "cert_subject": cert_subject,
        "hash_algo": hash_algo,
        "signature_algo": signature_algo,
        "serial_number": serial_number,
        "is_tv": apk_basic_info.get('is_tv', False),
        "is_leanback": apk_basic_info.get('is_leanback', False),
        "is_wearable": apk_basic_info.get('is_wearable', False),
        "detected_trackers": exodus_trackers.get("detected_trackers"),
        "total_trackers": exodus_trackers.get("total_trackers"),
        "trackers": exodus_trackers.get("trackers", []),
        "gplay_status": apk_basic_info.get('gplay_status', False),
        "privacy_policy_url": gplay_data.get('privacyPolicyURL', ''),
        "privacy_policy_text": gplay_data.get('privacyPolicyText', ''),
        "category": gplay_data.get('category', ''),
        "rating": gplay_data.get('rating', 'Not available'),  # Default to string to handle conversion later
        "data_safety": gplay_data.get('dataSafety', {}).get('collectedData', [])
    }

def create_tables(conn):
    with conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS beacon_app_info (
                file_hash TEXT PRIMARY KEY,
                package_name TEXT,
                version_code TEXT,
                version_name TEXT,
                perms JSONB,
                activities JSONB,
                services JSONB,
                receivers JSONB,
                sign_result TEXT,
                cert_sha1 TEXT,
                cert_sha256 TEXT,
                cert_issuer TEXT,
                cert_subject TEXT,
                hash_algo TEXT,
                signature_algo TEXT,
                serial_number TEXT,
                is_tv BOOLEAN,
                is_leanback BOOLEAN,
                is_wearable BOOLEAN,
                detected_trackers INTEGER,
                total_trackers INTEGER,
                gplay_status BOOLEAN,
                privacy_policy_url TEXT,
                privacy_policy_text TEXT,
                category TEXT,
                rating REAL
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS trackers (
                id SERIAL PRIMARY KEY,
                file_hash TEXT,
                package_name TEXT,
                tracker_name TEXT,
                tracker_url TEXT,
                CONSTRAINT fk_apk_info
                    FOREIGN KEY(file_hash)
                    REFERENCES beacon_app_info(file_hash)
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS data_safety (
                id SERIAL PRIMARY KEY,
                file_hash TEXT,
                package_name TEXT,
                data TEXT,
                optional BOOLEAN,
                purpose TEXT,
                data_type TEXT,
                CONSTRAINT fk_apk_info
                    FOREIGN KEY(file_hash)
                    REFERENCES beacon_app_info(file_hash)
            )
        ''')
        conn.commit()

def insert_trackers_data(conn, file_hash, package_name, trackers_data):
    with conn.cursor() as cur:
        for tracker in trackers_data:
            for name, url in tracker.items():
                cur.execute("""
                    INSERT INTO trackers (file_hash, package_name, tracker_name, tracker_url)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (file_hash, package_name, name, url))
        conn.commit()

def insert_data_safety(conn, file_hash, package_name, data_safety):
    with conn.cursor() as cur:
        for data in data_safety:
            cur.execute("""
                INSERT INTO data_safety (file_hash, package_name, data, optional, purpose, data_type)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (
                file_hash, package_name, data.get('data'), data.get('optional'), data.get('purpose'), data.get('type')
            ))
        conn.commit()

def clean_real_value(value):
    try:
        return float(value)
    except ValueError:
        return None

def insert_data(file):
    conn = psycopg2.connect("dbname=location_trackers user=aniketh password=password")
    try:
        create_tables(conn)

        with open(file, 'r') as f:
            print(f"Processing file: {file}")
            json_data = json.load(f)
        flat_data = flatten_json(json_data)

        # Validate required fields
        if not flat_data['file_hash'] or not flat_data['package_name']:
            print(f"Missing required fields in file: {file}")
            return

        rating = clean_real_value(flat_data['rating'])

        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO beacon_app_info (file_hash, package_name, version_code, version_name, perms, activities, services,
                receivers, sign_result, cert_sha1, cert_sha256, cert_issuer, cert_subject, hash_algo, signature_algo,
                serial_number, is_tv, is_leanback, is_wearable, detected_trackers, total_trackers, gplay_status,
                privacy_policy_url, privacy_policy_text, category, rating)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (file_hash) DO NOTHING
            """, (
                flat_data['file_hash'], flat_data['package_name'], flat_data['version_code'], flat_data['version_name'],
                json.dumps(flat_data['perms']), json.dumps(flat_data['activities']), json.dumps(flat_data['services']),
                json.dumps(flat_data['receivers']), flat_data['sign_result'], flat_data['cert_sha1'], flat_data['cert_sha256'],
                flat_data['cert_issuer'], flat_data['cert_subject'], flat_data['hash_algo'], flat_data['signature_algo'],
                flat_data['serial_number'], flat_data['is_tv'], flat_data['is_leanback'], flat_data['is_wearable'],
                flat_data['detected_trackers'], flat_data['total_trackers'], flat_data['gplay_status'],
                flat_data['privacy_policy_url'], flat_data['privacy_policy_text'], flat_data['category'], rating
            ))
            conn.commit()

        if flat_data['trackers']:
            insert_trackers_data(conn, flat_data['file_hash'], flat_data['package_name'], flat_data['trackers'])

        if 'data_safety' in flat_data and flat_data['data_safety']:
            insert_data_safety(conn, flat_data['file_hash'], flat_data['package_name'], flat_data['data_safety'])

        print(f"Successfully inserted data for file: {file}")
    except Exception as e:
        print(f"Error processing file {file}: {e}")
    finally:
        conn.close()

def process_files(files):
    print(f"Starting to process batch of {len(files)} files.")
    for file in files:
        insert_data(file)
    print(f"Finished processing batch of {len(files)} files.")

def main():
    directory = '/troll/lair0/beacons/acr-sa-new'
    json_files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith('.json')]

    num_processes = 110
    pool = Pool(processes=num_processes)

    chunk_size = len(json_files) // num_processes + (len(json_files) % num_processes > 0)
    chunks = [json_files[i:i + chunk_size] for i in range(0, len(json_files), chunk_size)]

    pool.map(process_files, chunks)
    pool.close()
    pool.join()

if __name__ == "__main__":
    main()
