# Flow data contract

Input is a JSON list. Each item requires `flow_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `duration_ms`, `packets`, and `bytes_sent`. Optional `direction` is one of inbound, outbound, or internal.

Example:

```json
{"flow_id":"f-001","timestamp":"2026-10-10T08:00:00Z","src_ip":"10.0.0.8","dst_ip":"203.0.113.8","src_port":51200,"dst_port":443,"protocol":"TCP","duration_ms":300,"packets":10,"bytes_sent":1200,"direction":"outbound"}
```

Allowed protocols are TCP, UDP, and ICMP. IP addresses must parse with Python's standard `ipaddress` module. A file is capped at 2 MB and 20,000 records. Flow IDs must be unique per import. Payload bytes and raw packet contents are not accepted.
