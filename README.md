# Catamaran: User Privacy Violation Detection in Mobile Logging

Logs are widely used in mobile apps for debugging and diagnosis. Unfortunately, they frequently expose personally identifiable information (PII) due to inattentive logging practices, leading to privacy hazards.

To address this, we introduce **Catamaran**, a framework to proactively detect PII violations in Android app logs. Catamaran takes a comprehensive approach combining dynamic and static analyses to fully discover privacy risks.

## Key Features

Inspired by the twin-hulled boat, Catamaran operates two analysis methods in parallel to provide powerful and comprehensive detection capabilities.

*   **Hybrid Analysis Methods**: Combines dynamic analysis (runtime monitoring) with static analysis (broader code coverage) to ensure both depth and breadth of detection.
*   **Comprehensive Leak Detection**: Monitors both standard `logcat` output and app-specific private log files to comprehensively capture Personally Identifiable Information (PII).
*   **Innovative Static Analysis**: Eliminates the need for predefined PII sources. It reconstructs potential log outputs and leverages a Large Language Model (LLM) to infer context, proactively identifying risks.
*   **Precise Source Attribution**: Pinpoints the origin of the log statement, clearly distinguishing whether a PII leak originates from the app's own code or a third-party library.

## Detection Methods

### Static Analysis
This toolchain is designed to automatically reconstruct and analyze logcat logs in Android applications.  
It enables researchers and security analysts to identify what information apps are logging, detect whether PII (Personally Identifiable Information) may be exposed, and understand which libraries or packages are responsible for printing such data.


**➡️ For detailed setup, configuration, and execution steps, please see: `static_analysis/README.md`**

### Dynamic Analysis

This toolchain is designed for the dynamic analysis of Android applications, focusing on real-time monitoring of log file writes and `logcat` logs to identify potential privacy leaks.

It operates by running a low-level monitoring program (`log-monitor`) on a rooted device, which uses rules provided by a companion Android application (`android-app`) to detect and flag specific behaviors.

**➡️ For detailed environment setup, compilation, and execution guides, please see: `dynamic_analysis/README.md`**

## Citation

If you use Catamaran in your research, please cite our paper:

> Chenxi Hou, Chun Jie Chong, Zhihao Yao, and Hui Peng. "Catamaran: User Privacy Violation Detection in Mobile Logging." In *Proceedings of the IEEE Secure Development Conference (SecDev)*, 2025.

BibTeX entry:
```bibtex
@inproceedings{hou2025catamaran,
  title={Catamaran: User Privacy Violation Detection in Mobile Logging},
  author={Hou, Chenxi and Chong, Chun Jie and Yao, Zhihao and Peng, Hui},
  booktitle={IEEE Secure Development Conference (SecDev)},
  year={2025}
}
```
