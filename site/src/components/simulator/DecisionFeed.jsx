export default function DecisionFeed({ records, onSelect, selected }) {
    return (
        <div className="feed">
            <h3>Evidence feed</h3>
            <ol>
                {records.map((record) => (
                    <li
                        key={record.flow_id}
                        className={
                            selected?.flow_id === record.flow_id
                                ? "selected"
                                : ""
                        }
                    >
                        <button
                            type="button"
                            className="flow-select"
                            onClick={() => onSelect(record)}
                            aria-pressed={selected?.flow_id === record.flow_id}
                        >
                            <span className="t">
                                {record.timestamp.slice(11, 19)}Z
                            </span>
                            <span className="to">{record.flow_id}</span>
                            <span className="sm">
                                {record.src_ip} → {record.dst_ip}:
                                {record.dst_port}
                            </span>
                            <span
                                className={`st ${record.severity === "high" ? "s5" : "s2"}`}
                            >
                                {record.severity}
                            </span>
                            <span className="r">
                                {record.rule_id} · {record.protocol} ·{" "}
                                {record.bytes_sent.toLocaleString()} bytes ·
                                Inspect evidence →
                            </span>
                        </button>
                    </li>
                ))}
            </ol>
        </div>
    );
}
