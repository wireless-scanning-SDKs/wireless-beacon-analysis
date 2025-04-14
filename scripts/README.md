# Analysis Scripts

This directory includes analysis notebooks and helper scripts used to support the evaluation of wireless-scanning SDKs in Android apps. The Jupyter notebooks were used to explore static and dynamic results, SDK behaviors, permission usage, and cross-library interactions. Python scripts assist with parsing, pre-processing, and extracting relevant metadata.

These notebooks were used during different stages of the analysis pipeline:

- `bt-analysis.ipynb`  
  → Explores **static analysis results**, focusing on SDK properties, declared permissions, data safety labels, and behaviors related to wireless scanning.

- `crosslib-analysis.ipynb`  
  → Analyzes **cross-library interactions**, revealing potential flows between embedded SDKs that may enable data aggregation or tracking.

- `da_analysis.ipynb`  
  → Explores **dynamic analysis logs**, including detection of:
  - PII dissemination by Apps/SDKs
  - Identifier bridging across Apps/SDKs
  - Wireless beacon scan events and signal collection during app execution

- `permission_pii_analysis.ipynb`  
  → Correlates **permissions** with access to **sensitive data** using API usage, supporting inference of PII exposure risk by third-party SDKs.

---

## 🛠️ Python Scripts (Metadata + Helpers)

These scripts handle parsing tasks and data extraction to support large-scale app analysis:


- `analyze_xlib_interaction.py`  
  → Detects and summarizes cross-SDK or cross-library interactions based on shared identifiers or behavior patterns.

- `get_target_sdk_version.py`  
  → Extracts the `targetSdkVersion` from APK metadata (via manifest parsing or `aapt`).

- `parse_aapt_get_apk_perm.py`  
  → Parses `aapt` output to extract declared permissions for each APK.

- `parse_rationale.py`  
  → Parses static layouts or UI elements to detect presence of rationale dialogs for location or Bluetooth permissions.

- `rationale_check.py`  
  → Validates whether apps comply with Android’s runtime permission best practices, especially for location access.


