#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETDPSYN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${NETDPSYN_DIR}/../.." && pwd)"

PCAP_PATH="${REPO_ROOT}/datasets/train.pcap"
DATASET_NAME="${DATASET_NAME:-train_pcap}"
EPSILON="${EPSILON:-2.0}"

if [[ ! -f "${PCAP_PATH}" ]]; then
  echo "Missing ${PCAP_PATH}. Make sure datasets/train.pcap is available." >&2
  exit 1
fi

echo "[NetDPSyn] Converting ${PCAP_PATH} to CSV (${DATASET_NAME})"
python3 "${NETDPSYN_DIR}/scripts/pcap_to_csv.py" \
  --pcap "${PCAP_PATH}" \
  --dataset-name "${DATASET_NAME}"

echo "[NetDPSyn] Preprocessing ${DATASET_NAME}.csv"
python3 "${NETDPSYN_DIR}/lib_preprocess/preprocess_network.py" \
  --dataset_name "${DATASET_NAME}"

echo "[NetDPSyn] Training with epsilon=${EPSILON}"
python3 "${NETDPSYN_DIR}/main.py" \
  --dataset_name "${DATASET_NAME}" \
  --epsilon "${EPSILON}"

OUTPUT_PCAP="${REPO_ROOT}/datasets/netdpsyn.pcap"
echo "[NetDPSyn] Converting synthesized CSV to ${OUTPUT_PCAP}"
python3 "${NETDPSYN_DIR}/scripts/csv_to_pcap.py" \
  --dataset-name "${DATASET_NAME}" \
  --epsilon "${EPSILON}" \
  --output "${OUTPUT_PCAP}"

echo "[NetDPSyn] Done. PCAP available at ${OUTPUT_PCAP}"
