#!/bin/bash

# Function to find and process APK files using GNU Parallel
process_apks() {
    find /troll/lair0/beacons/dataset/large_dataset/ \
         /naga/lair0/fuzzy_fitness/app_dataset/large_dataset/ \
         -type f -name "*.apk" | parallel -j 50 python beacon-finder.py {}
}

# Call the function
process_apks
