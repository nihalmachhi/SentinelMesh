export default function Offline() {
    return (
        <section className="sec wrap" id="offline">
            <div className="split">
                <div>
                    <h2>
                        Correlation connects related signals.{" "}
                        <span className="d2">
                            It keeps unrelated hosts apart.
                        </span>
                    </h2>
                    <p className="lede">
                        A shared timestamp is not enough to merge findings.
                        SentinelMesh requires a shared host and a bounded
                        event-time gap.
                    </p>
                    <dl className="facts">
                        <div>
                            <dt>Shared host</dt>
                            <dd>
                                At least one endpoint must appear in both
                                evidence sets.
                            </dd>
                        </div>
                        <div>
                            <dt>Time proximity</dt>
                            <dd>
                                Finding windows must be within the configurable
                                300-second default.
                            </dd>
                        </div>
                        <div>
                            <dt>Stable identity</dt>
                            <dd>
                                Incident IDs derive deterministically from the
                                primary host and evidence flow IDs.
                            </dd>
                        </div>
                    </dl>
                </div>
                <div className="stage" style={{ marginTop: 0 }}>
                    <div
                        className="ui"
                        style={{ padding: 16, display: "grid", gap: 12 }}
                    >
                        <div className="feed">
                            <h3>Two related findings</h3>
                            <ul className="tl">
                                <li>
                                    <span>10.20.0.250</span>
                                    <span className="o">08:00:00Z</span>
                                    <span>port diversity</span>
                                </li>
                                <li>
                                    <span>10.20.0.250</span>
                                    <span className="o">08:03:20Z</span>
                                    <span>SSH service</span>
                                </li>
                            </ul>
                            <p className="tiny" style={{ marginTop: 8 }}>
                                Same host, within five minutes: eligible to join
                                one incident.
                            </p>
                        </div>
                        <div className="feed">
                            <h3>Unrelated host</h3>
                            <div className="term">
                                <span className="q">
                                    10.20.1.12 · overlapping time · separate
                                    incident
                                </span>
                            </div>
                            <p className="tiny" style={{ marginTop: 8 }}>
                                Time overlap alone never merges unrelated hosts.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}
