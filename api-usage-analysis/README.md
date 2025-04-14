# API Usage Analysis

This module contains tools and configurations for analyzing Android apps based on their call graphs and API usage. It builds on and extends [AndroCFG](https://github.com/U039b/AndroCFG/) to identify privacy-relevant operations and beacon scanning capabilites.

## 🛠️ Usage

1. **Prepare APKs:** Decompile or preprocess your APKs as needed.
2. **Configure Rules:** Edit the JSON files in `bt_rules_json/` to define the behaviors you want to detect.
3. **Run Analysis:**
```bash
python3 batch_run.py
```
Note: Set base_path1 or base_path2 in the script to the location where you have stored your apks.
