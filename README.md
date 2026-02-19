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
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the analyzer against your Cilium YAML manifests or a directory containing them:

```bash
python cilium_analyzer/main.py <path_to_file_or_directory>
```

**Example:**

```bash
python cilium_analyzer/main.py ./cilium-manifests/
```

The tool will generate a report named `CILIUM_REPORT.md` in your current directory.
