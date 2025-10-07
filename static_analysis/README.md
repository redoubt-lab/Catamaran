# Static Analysis Toolchain for Catamaran 

This toolchain is designed to automatically reconstruct and analyze logcat logs in Android applications.  
It enables researchers and security analysts to identify what information apps are logging, detect whether PII (Personally Identifiable Information) may be exposed, and understand which libraries or packages are responsible for printing such data.

The workflow consists of three main components:
1. **Logcat Logs Reconstructor** – Reconstructs logcat logs and identifies caller signatures from APK bytecode using Soot and FlowDroid, and stores them in an SQLite database.
2. **LLM Analyzer (`llm_analyzer.py`)** – Uses a Large Language Model (LLM) to detect PII within the reconstructed logs and writes structured results to the database.
3. **Caller Analysis (`caller_analysis.py`)** – Analyzes the database results to identify which libraries or packages printed logs containing PII, and aggregates these findings across multiple APKs (with a CSV export).

---

## Dependencies & Environment

- **Java**
  - JDK 17 (recommended)
  - Android SDK (path to `platforms/` required)
  - Maven for building
- **Python**
  - Python 3.9+
  - Libraries:
    ```bash
    pip install openai pandas
    ```

---

## Workflow

```
[APK Files]
    │
    ▼
(1) Logcat Logs Reconstructor (Java)
    ├─ possible_output.db  (reconstructed logcat logs, caller signatures, APK package names)
    └─ app_result.db       (analysis runtime, memory usage, success/failure status)
    │
    ▼
(2) LLM Analyzer (Python)
    └─ final_result table  (PII detection results)
    │
    ▼
(3) Caller Analysis (Python)
    └─ CSV file            (exported statistics of which library or package printed logs containing PII)
```

---

## Step 1: APK Static Analysis (Java)

### Parameters to configure
In `Main.java`, set:

```java
// Path to folder containing APKs
private static final String APK_FOLDER_PATH = "/path/to/your/apks";

// Path to Android SDK 'platforms' directory
private static final String ANDROID_PLATFORM_DIR = "/path/to/your/android/sdk/platforms";
```

### How to run
```bash
# Build
mvn clean install

# Run from IDE or execute built JAR
```

### Output
- **possible_output.db** – APK package name, caller signature, reconstructed logcat log.
- **app_result.db** – runtime, memory usage, success/failure status.

---

## Step 2: LLM Analyzer (`llm_analyzer.py`)

### Parameters to configure
At the top of `llm_analyzer.py`:

```python
DB_PATH = "/path/to/possible_output.db"   # Path to SQLite DB
LLM_MODEL = "gpt-4o-mini"   # Model name, e.g., "gpt-4o" or "gpt-4o-mini"
OPENAI_CLIENT = OpenAI(api_key="your_api_key")  # API key
```

- `DB_PATH`: Path to `possible_output.db` generated earlier.  
- `LLM_MODEL`: Model to use (e.g., `gpt-4o`, `gpt-4o-mini`).  
- `api_key`: Your OpenAI API key.  

### How to run
```bash
python llm_analyzer.py
```

### Output
Creates/updates the **`final_result`** table inside the same DB.

---

## Step 3: Caller Analysis (`caller_analysis.py`)

### Parameters to configure
At the top of `caller_analysis.py`:

```python
db_path = "/path/to/possible_output.db"   # Path to DB
csv_file = "/path/to/output.csv"          # Export CSV path
exclude_list = ["c", "e", "e.w"]          # Package prefixes to ignore
```

- `db_path`: Path to the same DB (`possible_output.db`).  
- `csv_file`: Output CSV file path.  
- `exclude_list`: Filters meaningless package names (adjust if needed).  

### How to run
```bash
python caller_analysis.py
```

### Output
- **CSV file**: written to the path specified in `csv_file`, containing:  
  - library/package name  
  - number of APKs where it appeared  
  - detected PII types  

---

## Recommended Execution Order

1. **Logcat Logs Reconstructor (Java)** → produces `possible_output.db` & `app_result.db`  
2. **Run `llm_analyzer.py` (Python)** → writes `final_result` into `possible_output.db`  
3. **Run `caller_analysis.py` (Python)** → generates CSV
