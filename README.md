# Wireless beacon scanning tools and analysis code

This repository contains analysis code and datasets accompanying the paper:

> **"Your Signal, Their Data: An Empirical Privacy Analysis of Wireless-scanning SDKs in Android"**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## 📁 Repository Structure

Below is an overview of key folders and their purpose. Folders marked with 📄 have dedicated `README.md` files with more detail.

- `api-usage-analysis/`       📄  # Code for analyzing API usage via call graph extraction
- `beacon-sdk-detection/`      📄  # Scripts for detecting beacon SDKs in Android apps
- `datasets/`                 📄  # Static & dynamic analysis datasets developed in the paper
- `scripts/`                   📄  # Analysis notebooks and helper scripts
- `misc/`                          # Project images and logo assets
- `LICENSE`                        # GPLv3 license
- `README.md`                     # This file

---

## 📚 Subcomponents with Detailed Descriptions

### 🔹 [`api-usage-analysis/`](api-usage-analysis/README.md)

Contains code based on [AndroCFG]([https://github.com/U039b/AndroCFG](https://github.com/U039b/AndroCFG) for generating and analyzing call graphs from decompiled Android apps. Includes:
- `androcfg/`: Modified call graph extractor and rule-based behavior detection
- `bt_rules_json/`: Beacon and geofence-related rule definitions

### 🔹 [`beacon-sdk-detection/`](beacon-sdk-detection/README.md)

Tool to identify beacon-related SDKs in Android apps:
- `beacon-finder.py`: Scans smali code for beacon patterns
- `gplay-scrape.js`: Scraper for app metadata from Google Play
- Includes analysis config, Exodus tracker lists and JAR tools (e.g., baksmali)

### 🔹 [`datasets/`](datasets/README.md)

Empirical data developed in the paper:
- `static_analysis/`: CSVs produced after our static analysis. For example: API usage results. 
- `dynamic_analysis/`: Processed and summarized dynamic behavior log from our instrumentation.
- `crosslib_analysis/`: SDK-to-SDK behavior data 

### 🔹 [`scripts/`](scripts/README.md)

Miscellaneous Python and Jupyter scripts used to analyze static/dynamic outputs, SDK interactions, and permissions. Highlights include:
- `bt-analysis.ipynb`, `crosslib-analysis.ipynb`
- `analyze_xlib_interaction.py`: Investigates inter-SDK communication
- `parse_aapt_get_apk_perm.py`: Parses permission metadata from APKs

---

## 🧾 License

Licensed under the  [GNU GPLv3](LICENSE) license.

---

## 💰 Funding Support

Part of this research was supported by the Spanish National Cybersecurity Institute (INCIBE) under <i>Proyectos Estratégicos de Ciberseguridad -- CIBERSEGURIDAD EINA UNIZAR</i> and by the Recovery, Transformation and Resilience Plan funds, financed by the European Union (Next Generation).

![Funding logo](misc/images/INCIBE_logos.jpg)
