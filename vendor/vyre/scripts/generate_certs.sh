#!/usr/bin/env bash
set -e
mkdir -p certs
cargo run -p vyre-conform-runner -- run --backend wgpu --ops all > certs/wgpu_certs.json
echo "Generated certificates in certs/wgpu_certs.json"
