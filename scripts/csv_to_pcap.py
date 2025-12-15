#!/usr/bin/env python3
"""
Convert a NetDPSyn synthesized CSV back into a PCAP.
"""

import argparse
import socket
import struct
from pathlib import Path

import pandas as pd
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

import config_dpsyn


def int_to_ip(value: int) -> str:
    value = max(0, int(value))
    return socket.inet_ntoa(struct.pack("!I", value & 0xFFFFFFFF))


def build_transport_layer(proto: int, sport: int, dport: int, flags: int):
    if proto == 6:
        return TCP(sport=sport, dport=dport, flags=flags if flags is not None else "PA")
    if proto == 17:
        return UDP(sport=sport, dport=dport)
    # default to UDP-like headers for other protocols
    return UDP(sport=sport, dport=dport)


def csv_to_pcap(csv_path: Path, output_path: Path) -> None:
    df = pd.read_csv(csv_path)
    packets = []

    base_time = None
    for _, row in df.iterrows():
        src_ip = int_to_ip(row.get("srcip", 0))
        dst_ip = int_to_ip(row.get("dstip", 0))
        sport = int(row.get("srcport", 0) or 0)
        dport = int(row.get("dstport", 0) or 0)
        proto = int(row.get("proto", 17) or 17)
        ttl = int(row.get("ttl", 64) or 64)
        flags = row.get("flag", None)
        if pd.isna(flags):
            flags = None
        else:
            flags = int(flags)

        payload_len = int(row.get("pkt_len", row.get("byt", 0)) or 0)
        payload_len = max(payload_len - 40, 0)

        l4 = build_transport_layer(proto, sport, dport, flags)
        pkt = Ether() / IP(src=src_ip, dst=dst_ip, ttl=ttl, proto=proto) / l4 / Raw(
            b"\x00" * payload_len
        )

        ts_ns = row.get("time", row.get("ts", 0))
        if pd.isna(ts_ns):
            ts_ns = 0
        ts_ns = int(ts_ns)
        timestamp = ts_ns / 1e9
        if base_time is None:
            base_time = timestamp
        pkt.time = timestamp
        packets.append(pkt)

    if not packets:
        raise RuntimeError(f"No packets constructed from {csv_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    print(f"Wrote {len(packets)} packets to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Convert NetDPSyn CSV to PCAP.")
    parser.add_argument("--csv", help="Explicit path to synthesized CSV.")
    parser.add_argument(
        "--dataset-name",
        default="train_pcap",
        help="Dataset name used during preprocessing/training.",
    )
    parser.add_argument(
        "--epsilon",
        default="2.0",
        help="Epsilon tag used in synthesized CSV filename.",
    )
    parser.add_argument("--output", required=True, help="Output PCAP path.")
    args = parser.parse_args()

    if args.csv:
        csv_path = Path(args.csv)
    else:
        csv_name = f"{args.dataset_name}_{args.epsilon}.csv"
        csv_path = Path(config_dpsyn.SYNTHESIZED_RECORDS_PATH) / csv_name

    if not csv_path.exists():
        raise FileNotFoundError(f"Could not locate synthesized CSV at {csv_path}")

    csv_to_pcap(csv_path, Path(args.output))


if __name__ == "__main__":
    main()
