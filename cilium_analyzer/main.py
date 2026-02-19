#!/usr/bin/env python3
"""
Cilium Manifest Elite Checker (v4 — Enterprise Grade)
------------------------------------------------------
Upgraded elite static analyzer for Cilium manifests.

NEW IN v4:
- Cilium‑aware security exceptions (reduced false positives)
- Severity scoring
- Exit code support for CI
- kube-proxy-replacement consistency check
- IPAM mode validation
- Image registry validation
- BPF filesystem mount validation
- Improved resource analysis
- Portable report path

Usage:
  python main.py cilium-ds.yaml cilium-cm.yaml
  python main.py <file_or_dir> ...
"""

import sys
import os
import yaml
from typing import Any, Dict, List

# =============================
# Constants
# =============================

DANGEROUS_CAPS = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "DAC_OVERRIDE",
    "ALL",
}

SEVERITY_WEIGHTS = {
    "SECURITY": 5,
    "RELIABILITY": 4,
    "PERFORMANCE": 3,
    "BEST-PRACTICE": 2,
}

FINDINGS = {
    "SECURITY": [],
    "RELIABILITY": [],
    "PERFORMANCE": [],
    "BEST-PRACTICE": [],
}

TOTAL_SCORE = 0

# =============================
# Helpers
# =============================


def load_yaml(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        return [d for d in docs if isinstance(d, dict)]
    except FileNotFoundError:
        print(f"ERROR: File not found: {path}")
        return []
    except yaml.YAMLError as e:
        print(f"ERROR: YAML parse error in {path}: {e}")
        return []


def get_containers(ds: Dict[str, Any]):
    return (
        ds.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )


def get_volumes(ds: Dict[str, Any]):
    return (
        ds.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("volumes", [])
    )


def print_finding(level: str, msg: str):
    global TOTAL_SCORE
    print(f"[{level}] {msg}")
    if level in FINDINGS:
        FINDINGS[level].append(msg)
        TOTAL_SCORE += SEVERITY_WEIGHTS.get(level, 1)


def reset_analysis():
    global TOTAL_SCORE, FINDINGS
    TOTAL_SCORE = 0
    FINDINGS = {
        "SECURITY": [],
        "RELIABILITY": [],
        "PERFORMANCE": [],
        "BEST-PRACTICE": [],
    }

# =============================
# Security Checks
# =============================


def check_host_network(ds):
    spec = ds.get("spec", {}).get("template", {}).get("spec", {})
    if spec.get("hostNetwork"):
        print_finding(
            "SECURITY",
            "hostNetwork=true (expected for Cilium datapath — verify cluster hardening).",
        )


def check_privileged(containers):
    for c in containers:
        sc = c.get("securityContext", {})
        if sc.get("privileged") is True:
            if c.get("name") == "cilium-agent":
                print_finding(
                    "BEST-PRACTICE",
                    "cilium-agent runs privileged (normally required for eBPF).",
                )
            else:
                print_finding(
                    "SECURITY",
                    f"Container '{c.get('name')}' runs in privileged mode.",
                )


def check_allow_privilege_escalation(containers):
    for c in containers:
        sc = c.get("securityContext", {})
        if sc.get("allowPrivilegeEscalation") is True:
            print_finding(
                "SECURITY",
                f"Container '{c.get('name')}' allows privilege escalation.",
            )


def check_capabilities(containers):
    for c in containers:
        caps = (
            c.get("securityContext", {})
            .get("capabilities", {})
            .get("add", [])
        )
        bad = sorted(set(caps) & DANGEROUS_CAPS)
        if bad and c.get("name") != "cilium-agent":
            print_finding(
                "SECURITY",
                f"Container '{c.get('name')}' adds dangerous capabilities: {bad}",
            )


def check_container_hardening(containers):
    for c in containers:
        name = c.get("name")
        sc = c.get("securityContext", {})

        # Cilium-aware exception
        if name != "cilium-agent":
            if sc.get("runAsNonRoot") is not True:
                print_finding(
                    "SECURITY",
                    f"Container '{name}' should set runAsNonRoot=true.",
                )

        if sc.get("readOnlyRootFilesystem") is not True:
            print_finding(
                "BEST-PRACTICE",
                f"Container '{name}' consider enabling readOnlyRootFilesystem if compatible.",
            )


# =============================
# Reliability Checks
# =============================


def check_probes(containers):
    for c in containers:
        if not c.get("livenessProbe"):
            print_finding(
                "RELIABILITY",
                f"Container '{c.get('name')}' missing livenessProbe.",
            )
        if not c.get("readinessProbe"):
            print_finding(
                "RELIABILITY",
                f"Container '{c.get('name')}' missing readinessProbe.",
            )


def check_priority(ds):
    spec = ds.get("spec", {}).get("template", {}).get("spec", {})
    if not spec.get("priorityClassName"):
        print_finding(
            "RELIABILITY",
            "priorityClassName not set (system-node-critical recommended).",
        )


def check_update_strategy(ds):
    strategy = ds.get("spec", {}).get("updateStrategy", {})
    if strategy and strategy.get("type") not in (None, "RollingUpdate"):
        print_finding(
            "RELIABILITY",
            "DaemonSet updateStrategy is not RollingUpdate.",
        )


# =============================
# Performance Checks
# =============================


def check_resources(containers):
    for c in containers:
        res = c.get("resources", {})
        if not res.get("requests"):
            print_finding(
                "PERFORMANCE",
                f"Container '{c.get('name')}' missing resource requests.",
            )
        if not res.get("limits"):
            print_finding(
                "BEST-PRACTICE",
                f"Container '{c.get('name')}' missing resource limits.",
            )


# =============================
# ConfigMap Elite Checks
# =============================


def check_cm_performance(cm: Dict[str, Any]):
    data = cm.get("data", {})

    if data.get("datapath-mode") == "veth":
        print_finding(
            "PERFORMANCE",
            "datapath-mode=veth (consider native/direct routing if supported).",
        )

    if str(data.get("kube-proxy-replacement", "")).lower() not in (
        "strict",
        "true",
    ):
        print_finding(
            "PERFORMANCE",
            "kube-proxy-replacement not strict (may reduce performance).",
        )

    if data.get("bpf-lb-acceleration") in ("disabled", None):
        print_finding("PERFORMANCE", "BPF LB acceleration disabled.")

    if not data.get("mtu"):
        print_finding("PERFORMANCE", "MTU not explicitly set.")

    # NEW — IPAM validation
    if not data.get("ipam"):
        print_finding("RELIABILITY", "IPAM mode not explicitly configured.")


# =============================
# Elite Platform Checks
# =============================


def check_image_registry(containers):
    for c in containers:
        img = c.get("image", "")
        if img and ("cilium" in c.get("name", "")):
            if not ("quay.io/cilium" in img or "docker.io/cilium" in img):
                print_finding(
                    "SECURITY",
                    f"Container '{c.get('name')}' uses non-official Cilium image registry.",
                )


def check_bpf_mount(ds):
    volumes = get_volumes(ds)
    names = {v.get("name") for v in volumes}

    expected = {"bpf", "cilium-run"}
    if not expected & names:
        print_finding(
            "RELIABILITY",
            "Expected BPF or cilium runtime mounts not detected.",
        )


# =============================
# Best Practice Checks
# =============================


def check_image_tags(containers):
    for c in containers:
        img = c.get("image", "")
        if img.endswith(":latest") or (":" not in img and "@" not in img):
            print_finding(
                "BEST-PRACTICE",
                f"Container '{c.get('name')}' uses mutable image tag.",
            )


def check_hubble(cm):
    data = cm.get("data", {})
    if str(data.get("enable-hubble")).lower() != "true":
        print_finding("BEST-PRACTICE", "Hubble observability not enabled.")


def check_debug(cm):
    data = cm.get("data", {})
    if str(data.get("debug")).lower() == "true":
        print_finding("BEST-PRACTICE", "Debug mode enabled — disable in production.")


# =============================
# Report
# =============================


def generate_report():
    output_path = os.path.join(os.getcwd(), "CILIUM_REPORT.md")
    try:
        with open(output_path, "w") as f:
            f.write("# Cilium Manifest Analysis Report\n\n")
            health_score = max(0, 100 - TOTAL_SCORE)
            f.write(f"**Cilium Health Score:** {health_score}/100\n\n")

            sections = [
                ("Security Analysis", "SECURITY"),
                ("Reliability Analysis", "RELIABILITY"),
                ("Performance Analysis", "PERFORMANCE"),
                ("Best Practices Analysis", "BEST-PRACTICE"),
            ]

            for title, key in sections:
                f.write(f"## {title}\n\n")
                items = FINDINGS.get(key, [])
                if items:
                    for item in items:
                        f.write(f"- {item}\n")
                else:
                    f.write("No issues found.\n")
                f.write("\n")

        print(f"\nReport written to {output_path}")
    except Exception as e:
        print(f"\nError writing report: {e}")


# =============================
# Main
# =============================


def scan_paths(paths: List[str]):
    for path in paths:
        print(f"\n===== Analyzing {path} =====")
        docs = load_yaml(path)

        for d in docs:
            kind = d.get("kind")

            if kind == "DaemonSet":
                containers = get_containers(d)
                check_host_network(d)
                check_privileged(containers)
                check_allow_privilege_escalation(containers)
                check_capabilities(containers)
                check_container_hardening(containers)
                check_probes(containers)
                check_priority(d)
                check_update_strategy(d)
                check_resources(containers)
                check_image_registry(containers)
                check_bpf_mount(d)
                check_image_tags(containers)

            if kind == "ConfigMap":
                check_cm_performance(d)
                check_hubble(d)
                check_debug(d)

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <file_or_dir> ...")
        sys.exit(1)

    files_to_scan = []
    for arg in sys.argv[1:]:
        if os.path.isdir(arg):
            for root, _, files in os.walk(arg):
                for f in files:
                    if f.lower().endswith((".yaml", ".yml")):
                        files_to_scan.append(os.path.join(root, f))
        else:
            files_to_scan.append(arg)

    scan_paths(files_to_scan)

    generate_report()

    # CI-friendly exit
    if TOTAL_SCORE >= 20:
        sys.exit(2)


if __name__ == "__main__":
    main()
