# Cilium Manifest Elite Checker

A static analysis tool for Cilium CNI manifests (DaemonSet & ConfigMap) to detect security risks, performance issues, and best practice violations.

## Features

- **Security**: Checks for privileged containers, dangerous capabilities, host networking, and image registries.
- **Performance**: Validates datapath modes, MTU settings, BPF acceleration, and resource requests.
- **Reliability**: Checks for probes, update strategies, priority classes, and IPAM configuration.
- **Best Practices**: Validates image tags, Hubble enablement, and debug modes.

## Scoring System

The tool calculates a **Cilium Health Score** (0-100) by starting at 100 and deducting points for each issue found based on severity:

- **Security Issues**: -5 points
- **Reliability Issues**: -4 points
- **Performance Issues**: -3 points
- **Best Practices**: -2 points

## Installation

1. Clone the repository.
2. Install dependencies:

   **For Command Line Interface (CLI):**

   ```bash
   pip install -r requirements.txt
   ```

   **For Graphical User Interface (GUI):**

   ```bash
   pip install -r requirements-gui.txt
   ```

## Usage

### Command Line Interface (CLI)

Run the analyzer against your Cilium YAML manifests or a directory containing them:

```bash
python cilium_analyzer/main.py <path_to_file_or_directory>
```

**Example:**

```bash
python cilium_analyzer/main.py ./cilium-manifests/
```

The tool will generate a report named `CILIUM_REPORT.md` in your current directory.

### Graphical User Interface (GUI)

Launch the web interface to upload and analyze files interactively:

```bash
streamlit run cilium_analyzer/gui.py
```

<img width="2862" height="1554" alt="2228BC62-DF7F-453D-B7B6-317621E007D6" src="https://github.com/user-attachments/assets/819690c2-2179-4f5a-953d-80ffd548dc8f" />

<img width="2856" height="1554" alt="73DDEBFB-2492-48D0-8CBD-3F63360F2E23" src="https://github.com/user-attachments/assets/a2b33d14-fbdf-4e10-b206-c50dee232f15" />

