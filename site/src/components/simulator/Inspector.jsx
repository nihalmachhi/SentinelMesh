export default function Inspector({ sim }) {
    const flow = sim.snapshot.selected;
    if (!flow)
        return (
            <div className="ui insp" id="insp" aria-live="polite">
                <p>Select a flow from the evidence feed.</p>
            </div>
        );
    return (
        <div className="ui insp" id="insp" aria-live="polite">
            <div className="ib">
                <span
                    className={`pill ${flow.severity === "high" ? "bad" : "warn"}`}
                >
                    {flow.severity}
                </span>
                <b className="mono">{flow.flow_id}</b>
                <span className="pol">{flow.rule_id}</span>
            </div>
            <p className="why">
                This synthetic flow matched an explainable triage rule. The
                finding is a prompt for review, not a verdict.
            </p>
            <div className="sh">Linked flow evidence</div>
            <ul className="irs">
                {[
                    ["Timestamp", flow.timestamp],
                    ["Source", `${flow.src_ip}:${flow.src_port}`],
                    ["Destination", `${flow.dst_ip}:${flow.dst_port}`],
                    ["Protocol", flow.protocol],
                    ["Bytes sent", flow.bytes_sent.toLocaleString()],
                    ["Direction", flow.direction],
                ].map(([label, value]) => (
                    <li className="ir" key={label}>
                        <div className="irh">
                            <span>{label}</span>
                            <span className="mono">{value}</span>
                        </div>
                    </li>
                ))}
            </ul>
            <div className="sh">ATT&amp;CK context</div>
            <p className="irm">
                Contextual candidate only. Flow metadata does not establish
                intent or compromise.
            </p>
        </div>
    );
}
