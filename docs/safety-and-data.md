# Safety and data handling

- The sample is synthetic and the dashboard is designed for loopback. The server rejects non-loopback bind addresses.
- Input is JSON flow metadata only. The MVP does not parse PCAP, inspect payloads, capture traffic, or run arbitrary commands.
- Request/import size and row count are bounded. IPs, protocols, ports, and counters are validated before persistence.
- Detection scores are fixed demo rule scores. They are not calibrated probabilities and do not establish attacker intent.
- The assistant builds reports only from stored evidence and labels its reasoning as hypotheses. It has no shell or network-control tool.
- A response action needs a named analyst and an allow-listed action; the record states simulated-only and network_changed=false.
- SQLite database and reports can contain sensitive host metadata when users substitute real inputs. Keep data local, use lab data, control filesystem access, and delete generated output when no longer needed.
- This demo has no authentication. Do not expose the server beyond localhost.
