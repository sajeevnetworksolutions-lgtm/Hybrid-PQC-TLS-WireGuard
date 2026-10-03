"""
Publication-Quality Visualization Suite
Generates IEEE standard figures for M.Tech Dissertation Chapters.
"""

import os
import json
import matplotlib.pyplot as plt
import numpy as np


def generate_all_plots(benchmark_json_path: str = "benchmark_results.json", output_dir: str = "visualization"):
    os.makedirs(output_dir, exist_ok=True)
    with open(benchmark_json_path, "r") as f:
        data = json.load(f)

    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    plt.rcParams["font.sans-serif"] = "Arial"
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.size"] = 10

    # -------------------------------------------------------------
    # FIGURE 1: Handshake Latency vs Packet Loss Rate
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    loss_curves = data["network_loss_curves"]
    x = loss_curves["loss_rates_percent"]

    ax.plot(x, loss_curves["X25519"], "o-", color="#1f77b4", label="Classic Baseline (X25519)", linewidth=2)
    ax.plot(x, loss_curves["X25519+ML-KEM-768"], "s--", color="#ff7f0e", label="Static Hybrid (X25519 + ML-KEM-768)", linewidth=2)
    ax.plot(x, loss_curves["X25519+ML-KEM-1024"], "^-.", color="#d62728", label="Static Hybrid (X25519 + ML-KEM-1024)", linewidth=2)
    ax.plot(x, loss_curves["Adaptive_Optimization"], "D-", color="#2ca02c", label="Proposed Adaptive Optimization", linewidth=2.5)

    ax.set_title("Fig. 1: Handshake Latency vs Packet Loss Rate (WAN Link)", fontsize=11, fontweight="bold")
    ax.set_xlabel("Packet Loss Rate (%)", fontsize=10)
    ax.set_ylabel("Time to First Byte (TTFB) Latency (ms)", fontsize=10)
    ax.legend(loc="upper left", frameon=True)
    ax.grid(True, linestyle="--", alpha=0.6)
    fig.tight_layout()
    fig1_path = os.path.join(output_dir, "fig1_latency_vs_loss.png")
    fig.savefig(fig1_path)
    plt.close(fig)
    print(f"[+] Saved Figure 1 to: {fig1_path}")

    # -------------------------------------------------------------
    # FIGURE 2: Handshake Throughput vs Concurrency
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    tput_data = data["throughput"]
    conc = tput_data["concurrency_levels"]
    suites = tput_data["suites"]

    colors = ["#1f77b4", "#2ca02c", "#ff7f0e", "#d62728", "#9467bd"]
    for (s_name, vals), col in zip(suites.items(), colors):
        ax.plot(conc, vals, "o-", label=s_name, color=col, linewidth=2)

    ax.set_title("Fig. 2: Handshake Throughput vs Concurrency Scaling", fontsize=11, fontweight="bold")
    ax.set_xlabel("Concurrent Client Workers", fontsize=10)
    ax.set_ylabel("Handshake Throughput (conns / sec)", fontsize=10)
    ax.legend(loc="upper left", frameon=True)
    ax.grid(True, linestyle="--", alpha=0.6)
    fig.tight_layout()
    fig2_path = os.path.join(output_dir, "fig2_throughput_scaling.png")
    fig.savefig(fig2_path)
    plt.close(fig)
    print(f"[+] Saved Figure 2 to: {fig2_path}")

    # -------------------------------------------------------------
    # FIGURE 3: Key & Ciphertext Size Breakdown
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
    mem_data = data["memory_profile"]
    s_names = list(mem_data.keys())
    pk_sizes = [mem_data[s]["public_key_bytes"] for s in s_names]
    ct_sizes = [mem_data[s]["ciphertext_bytes"] for s in s_names]

    bar_width = 0.35
    indices = np.arange(len(s_names))
    ax.bar(indices - bar_width/2, pk_sizes, bar_width, label="Public Key Size (B)", color="#3498db")
    ax.bar(indices + bar_width/2, ct_sizes, bar_width, label="Ciphertext Size (B)", color="#e74c3c")
    ax.axhline(y=1500, color="gray", linestyle="--", label="Standard Ethernet MTU (1500 B)")

    ax.set_title("Fig. 3: Cryptographic Key & Ciphertext Payload Comparison", fontsize=11, fontweight="bold")
    ax.set_xticks(indices)
    ax.set_xticklabels(s_names, rotation=25, ha="right", fontsize=9)
    ax.set_ylabel("Payload Size (Bytes)", fontsize=10)
    ax.legend(loc="upper left", frameon=True)
    ax.grid(True, linestyle="--", alpha=0.5)
    fig.tight_layout()
    fig3_path = os.path.join(output_dir, "fig3_key_sizes.png")
    fig.savefig(fig3_path)
    plt.close(fig)
    print(f"[+] Saved Figure 3 to: {fig3_path}")

    # -------------------------------------------------------------
    # FIGURE 4: Hardware Energy Dissipation (x86 vs ARM Edge)
    # -------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
    hw_data = data["hardware_energy"]
    s_names = list(hw_data["x86_64_server"].keys())
    x86_energy = [hw_data["x86_64_server"][s]["energy_microjoules"] for s in s_names]
    arm_energy = [hw_data["arm_cortex_edge"][s]["energy_microjoules"] for s in s_names]

    bar_width = 0.35
    indices = np.arange(len(s_names))
    ax.bar(indices - bar_width/2, x86_energy, bar_width, label="x86_64 Cloud Server (uJ)", color="#2ecc71")
    ax.bar(indices + bar_width/2, arm_energy, bar_width, label="ARM Cortex-A53 Edge (uJ)", color="#f39c12")

    ax.set_title("Fig. 4: Energy Dissipation per Handshake by Hardware Architecture", fontsize=11, fontweight="bold")
    ax.set_xticks(indices)
    ax.set_xticklabels(s_names, rotation=25, ha="right", fontsize=9)
    ax.set_ylabel("Energy Dissipation (microjoules / handshake)", fontsize=10)
    ax.legend(loc="upper left", frameon=True)
    ax.grid(True, linestyle="--", alpha=0.5)
    fig.tight_layout()
    fig4_path = os.path.join(output_dir, "fig4_energy_dissipation.png")
    fig.savefig(fig4_path)
    plt.close(fig)
    print(f"[+] Saved Figure 4 to: {fig4_path}")


if __name__ == "__main__":
    generate_all_plots()
