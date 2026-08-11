# Daemon response framing

The daemon response encoder writes JSON directly into the bounded transport buffer and backpatches the four-byte big-endian length prefix. The legacy comparison serializes the same response into a temporary `Vec<u8>` and then copies that complete body into the transport buffer.

## Result

| Metric | Legacy | Direct | Change |
|---|---:|---:|---:|
| Temporary complete response bodies | 1 | 0 | 100% eliminated |
| Temporary body bytes per measured frame | 62,914,589 | 0 | 100% eliminated |
| Median serialization | 46.001 ms | 26.840 ms | 1.714x faster |
| Peak process RSS | 189,856 KiB | 128,284 KiB | 61,572 KiB lower (32.43%) |

The response value and completed transport frame remain live in both modes. Removing one of three response-sized live objects limits total peak-RSS improvement to less than 2x. The direct encoder eliminates the avoidable staging object and body copy completely.

## Method

The release-mode harness encoded a valid `Response::Error` containing a 60 MiB message. Its JSON body was 62,914,589 bytes and its complete frame was 62,914,593 bytes, below the 67,108,864-byte body ceiling. Each mode encoded the response seven times into a fresh `BytesMut`; the table reports the median. Separate processes provided peak RSS through GNU `time -v`.

The synthetic response isolates the production framing path from scanner and socket scheduling. It does not claim mass-scan throughput. The committed JSON receipt binds the source revision, executable hash, host, workload, trial count, timing, memory, and exact framing contracts.

## Compatibility checks

The framing regressions compare direct output byte-for-byte with `serde_json::to_vec`, including nested values, escaped bytes, a pre-populated destination buffer, and the production response writer. Cap failures and serializer failures after partial output must restore the destination buffer exactly. The decoder continues to reject announced bodies above 64 MiB.

Receipt: [`daemon-response-framing.json`](daemon-response-framing.json)
