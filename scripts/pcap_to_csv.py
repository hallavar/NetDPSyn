#!/usr/bin/env python3
"""
Utility to convert a PCAP capture into the CSV schema expected by NetDPSyn.

It parses each IP packet, extracts header fields needed by fields.json,
computes simple per-flow inter-arrival times, and writes the rows into
lib_preprocess/temp_data/raw_data/<dataset>.csv so the standard preprocessing
and training commands can be reused without hand-editing inputs.
"""

import argparse
import socket
import struct
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd
from scapy.all import IP, PcapReader

import config_dpsyn


def inet_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return 0


def pick_ports(pkt) -> Tuple[int, int]:
    for layer in ("TCP", "UDP"):
        if pkt.haslayer(layer):
            l = pkt[layer]
            return int(getattr(l, "sport", 0) or 0), int(getattr(l, "dport", 0) or 0)
    return 0, 0


def main():
    parser = argparse.ArgumentParser(description="Convert a PCAP into NetDPSyn raw CSV format.")
    parser.add_argument("--pcap", required=True, help="Input PCAP file.")
    parser.add_argument(
        "--dataset-name",
        default="custom",
        help="Basename for the generated CSV (maps to dataset_name in NetDPSyn).",
    )
    parser.add_argument(
        "--output-csv",
        help="Optional explicit output path. Defaults to lib_preprocess/temp_data/raw_data/<dataset-name>.csv",
    )
    parser.add_argument("--label", default="train", help="Label column value to embed in the CSV.")
    parser.add_argument("--flow-type", default="pcap", help="Type column value for downstream tasks.")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise FileNotFoundError(pcap_path)

    if args.output_csv:
        out_csv = Path(args.output_csv)
    else:
        out_csv = Path(config_dpsyn.RAW_DATA_PATH) / f"{args.dataset_name}.csv"

    out_csv.parent.mkdir(parents=True, exist_ok=True)

    flow_last_ts: Dict[Tuple[int, int, int, int, int], int] = {}
    rows = []

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            src_ip_int = inet_to_int(ip.src)
            dst_ip_int = inet_to_int(ip.dst)
            sport, dport = pick_ports(pkt)
            proto = int(getattr(ip, "proto", 0) or 0)
            ts_ns = int(float(pkt.time) * 1e9)

            flow_key = (src_ip_int, dst_ip_int, sport, dport, proto)
            prev_ts = flow_last_ts.get(flow_key, ts_ns)
            td_ns = max(ts_ns - prev_ts, 0)
            flow_last_ts[flow_key] = ts_ns

            pkt_len = int(len(pkt))
            row = {
                "srcip": src_ip_int,
                "dstip": dst_ip_int,
                "srcport": sport,
                "dstport": dport,
                "proto": proto,
                "ts": ts_ns,
                "td": td_ns,
                "pkt": 1,
                "byt": pkt_len,
                "label": args.label,
                "type": args.flow_type,
                "time": ts_ns,
                "pkt_len": pkt_len,
                "version": int(getattr(ip, "version", 0) or 0),
                "ihl": int(getattr(ip, "ihl", 0) or 0),
                "tos": int(getattr(ip, "tos", 0) or 0),
                "id": int(getattr(ip, "id", 0) or 0),
                "flag": int(getattr(ip, "flags", 0) or 0),
                "off": int(getattr(ip, "frag", 0) or 0),
                "ttl": int(getattr(ip, "ttl", 0) or 0),
                "chksum": int(getattr(ip, "chksum", 0) or 0),
            }
            rows.append(row)

    if not rows:
        raise RuntimeError(f"No IP packets found in {pcap_path}")

    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)
    print(f"Wrote {len(df)} rows to {out_csv}")


if __name__ == "__main__":
    main()
