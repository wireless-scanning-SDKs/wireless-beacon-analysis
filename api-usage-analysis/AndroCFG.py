#!/usr/bin/env python3
import argparse
import os
import hashlib  # Import the hashlib library

from androcfg.call_graph_extractor import CFG


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apk", help="APK to be analyzed", type=str, required=False)
    parser.add_argument("-o", "--output", help="Output directory", type=str, required=False)
    parser.add_argument("-r", "--rules", help="JSON file containing rules", type=str, required=False)
    parser.add_argument("-f", "--file", help="Sets the output file type for the code extraction (bmp, html, raw). Default is bmp", type=str, choices=['bmp', 'html', 'raw'], required=False)
    parser.add_argument("-l", "--localhost", help="Use localhost method for output directory naming (hash based)", action='store_true')
    args = parser.parse_args()

    if not args.apk:
        args.apk = '/troll/lair0/beacons/joel/Alphonso/5C20FF532F667459225DCCA9D06BC27ED2D977879C8CBCEEDD88005DE4AAA871.apk'

    output_root_dir = '/data/localhost/androcfg_output/'

    if not os.path.exists(output_root_dir):
        os.makedirs(output_root_dir)

    # Function to compute the SHA-256 hash of the APK file
    def get_file_hash(filepath):
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    # Conditional output directory naming based on the --localhost flag
    if args.localhost:
        apk_hash = get_file_hash(args.apk)
        args.output = output_root_dir + apk_hash
    else:
        if args.output:
            args.output = output_root_dir + args.output
        else:
            args.output = output_root_dir + os.path.basename(args.apk).split('.apk')[0]
    
    print("Output directory set to:", args.output)

    if not os.path.exists(args.output):
        os.makedirs(args.output)
    else:
        print("Output directory already exists. Exiting.")
        exit(1)

    if args.rules:
        c = CFG(args.apk, args.output, args.rules, args.file)
    else:
        c = CFG(args.apk, args.output, args.file)
    c.compute_rules(timeout=200)
    c.generate_md_report()


if __name__ == '__main__':
    main()
    print("Completed the analysis.")
