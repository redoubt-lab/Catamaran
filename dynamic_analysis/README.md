# Dynamic Analysis Toolchain for Catamaran

This toolchain is designed for the dynamic analysis of Android applications, focusing on real-time monitoring of log file writes and `logcat` logs to identify potential privacy leaks.

It operates by running a low-level monitoring program (`log-monitor`) on a rooted device, which uses rules provided by a companion Android application (`android-app`) to detect and flag specific behaviors.

---

## Components

1.  **`android-app` (Rule Configuration App)** – An Android application that gathers device-specific sensitive information (e.g., IMEI, GPS) and generates a configuration file for the monitor.
2.  **`log-monitor` (Core Monitoring Program)** – A native executable that runs on the device. It utilizes eBPF and `logcat` to monitor logs and matches it against the rules to detect privacy violations.

---

## Dependencies & Environment

- **Root Access**: The Android device must be rooted.
- **Android Version**: Android 10 or later is recommended for better eBPF support, with Android 13 thoroughly tested.
- **Android NDK**: Required for compiling `log-monitor`.
- **ADB**: Used for deploying files and executing commands.
- **Build System**: Ubuntu 22.04.
---

## Build Instructions

### How to Compile `log-monitor`

The `log-monitor` is a C project and must be cross-compiled for the target Android architecture (e.g., `arm64-v8a`).

1.  **Set up Android NDK**: Download and extract the Android NDK. Set the `NDK_ROOT` environment variable to its path.

2.  **Configure Build Environment**: Set up environment variables for the cross-compiler. For `arm64-v8a`:
    ```bash
    export ANDROID_NDK_HOME=PATH_TO_NDK
    export PATH=$ANDROID_NDK_HOME:$PATH
    sudo apt update
    sudo apt install -y \
        make \
        gcc-aarch64-linux-gnu \
        build-essential \
        pkg-config \
        clang \
        llvm \
        libelf-dev \
        zlib1g-dev \
        libcap-dev \
        libsqlite3-dev \
        android-tools-adb
    ```

3.  **Compile**: Navigate to the `log-monitor` directory and run `make`.
    ```bash
    make -f Makefile-Android-ARM
    ```

### Output
- **`log-monitor/logmonitor`**: The compiled native executable for your target device.

---

## Workflow

```
[android-app]
    │ (Generates rules.config)
    ▼
[log-monitor on device]
    │ (Monitors logcat and log file writes)
    ▼
[violations.db]
    │ (Contains detected privacy leaks)
    ▼
[Analysis on Host]
```

---

## Step 1: Install `android-app` and Generate Rules

### How to run
1.  Build the `android-app` project to generate an APK.
2.  Install the app onto the rooted Android device:
    ```bash
    adb install /path/to/your/app.apk
    ```
3.  Open the app, grant the required permissions (Location, Phone State, etc.).
4.  Fill in the sensitive information and click “Save Config.”


---

## Step 2: Deploy and Run `log-monitor`

### How to run
1.  Build the `log-monitor` project to generate the compiled native executable.
2.  Push the following files from the`log-monitor` directory to the device (Before pushing any files, set the working directory to `log-monitor`):
    ```bash
    adb push logmonitor /data/local/tmp/logmonitor/logmonitor
    adb push filter.config /data/local/tmp/logmonitor/filter.config
    adb push excluded.file.suffix.config /data/local/tmp/logmonitor/excluded.file.suffix.config
    adb push magic-android-arm.mgc /data/local/tmp/logmonitor/magic.mgc
    adb push btf/* /data/local/tmp/logmonitor/
3.  Grant execute permissions:
    ```bash
    adb shell "chmod +x /data/local/tmp/logmonitor/logmonitor"
    ```
4.  Run the monitor with root privileges:
    ```bash
    adb shell su -c '/data/local/tmp/logmonitor/logmonitor'
    ```

### Output
- **`/data/local/tmp/logmonitor/violations.db`**: A database containing all detected violations.

---

## Step 3: Review Analysis Results

### How to run
1.  Perform actions on the target app to trigger logging or file I/O.
2.  Pull the results database from the device to your host machine:
    ```bash
    adb pull /data/local/tmp/logmonitor/violations.db
    ```
3.  Use any SQLite client to open `violations.db` and inspect the `violations` table.