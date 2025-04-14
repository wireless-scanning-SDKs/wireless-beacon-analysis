#!/bin/bash

# Define the directories for APKs and results
APK_DIRS="/troll/lair0/beacons/dataset/large_dataset/ /naga/lair0/fuzzy_fitness/app_dataset/large_dataset/"
RES_DIR="/troll/lair0/beacons/acr-sa-new"
RES_DIR_2="/troll/lair0/beacons/acr-sa"

# Function to check and process APK files
check_and_process_apk() {
    local file="$1"
    echo "Checking file: $file"

    # Calculate hash using Python and ensure it is lowercase
    hash=$(python -c "import sys; from utils import sha256; print(sha256(sys.argv[1]).lower())" "$file")

    # Construct paths to JSON files
    json1="$RES_DIR/$hash.json"
    json2="$RES_DIR_2/$hash.json"

    # Check if the APK has already been processed
    if [ -f "$json1" ] || [ -f "$json2" ]; then
        echo "BASH Skipping $file as it has already been processed."
    else
        echo "Processing $file with acr-finder.py"
        python acr-finder.py "$file"
    fi
}

export RES_DIR
export RES_DIR_2

# Export the function so it can be used by parallel
export -f check_and_process_apk

# Function to process APK files in parallel
process_apks() {
    # Find all APK files and process them in parallel
    find $APK_DIRS -type f -name "*.apk" | parallel -j 80 check_and_process_apk
}

# Call the function
process_apks

