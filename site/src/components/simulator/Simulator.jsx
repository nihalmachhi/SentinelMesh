import DecisionFeed from "./DecisionFeed.jsx";

const SCENARIOS = [
    { key: "mixed", label: "Mixed" },
    { key: "port scan", label: "Port scan" },
    { key: "high egress", label: "High egress" },
    { key: "beacon", label: "Periodic" },
];

export default function Simulator({ sim }) {
    const { snapshot } = sim;
    return (
        <div className="stage" id="demo">
            <div
                className="ui"
                role="group"
                aria-label="Synthetic SentinelMesh flow review dashboard"
            >
                <div className="ui-bar">
                    <div className="ui-title">
                        <span className="live" aria-hidden="true" />
                        SentinelMesh <small>synthetic flow review</small>
                    </div>
                    <div className="kpis">
                        <div>
                            <b>600</b>
                            <span>flows</span>
                        </div>
                        <div>
                            <b>17</b>
                            <span>findings</span>
                        </div>
                        <div>
                            <b>4</b>
                            <span>incidents</span>
                        </div>
                    </div>
                </div>
                <div className="ctl">
                    <div
                        className="seg"
                        role="radiogroup"
                        aria-label="Synthetic flow scenario"
                    >
                        {SCENARIOS.map((scenario) => (
                            <button
                                key={scenario.key}
                                type="button"
                                role="radio"
                                aria-checked={sim.mode === scenario.key}
                                onClick={() => sim.setMode(scenario.key)}
                            >
                                {scenario.label}
                            </button>
                        ))}
                    </div>
                    <div className="acts">
                        <button
                            className="ab"
                            type="button"
                            aria-pressed={sim.auto}
                            onClick={() => sim.setAuto(!sim.auto)}
                        >
                            {sim.auto ? "Pause preview" : "Auto preview"}
                        </button>
                        <button
                            className="ab pri"
                            type="button"
                            onClick={sim.burst}
                        >
                            Add 20 preview flows
                        </button>
                        <button
                            className="ab"
                            type="button"
                            onClick={sim.reset}
                        >
                            Reset
                        </button>
                    </div>
                </div>
                <div className="main">
                    <div className="stack">
                        <div className="bk">
                            <div className="bk-h">
                                <h3>Sample pipeline</h3>
                                <span className="pill ok">offline fixture</span>
                            </div>
                            <dl className="m">
                                <div>
                                    <dt>Flow records</dt>
                                    <dd>600</dd>
                                </div>
                                <div>
                                    <dt>Findings</dt>
                                    <dd>17</dd>
                                </div>
                                <div>
                                    <dt>Incidents</dt>
                                    <dd>4</dd>
                                </div>
                                <div>
                                    <dt>Preview events</dt>
                                    <dd>{snapshot.previewCount}</dd>
                                </div>
                            </dl>
                            <span className="bar">
                                <i style={{ width: "100%" }} />
                            </span>
                        </div>
                        <div className="bk">
                            <div className="bk-h">
                                <h3>Selected scenario</h3>
                                <span className="pill warn">synthetic</span>
                            </div>
                            <dl className="m">
                                <div>
                                    <dt>Source host</dt>
                                    <dd>10.20.0.250</dd>
                                </div>
                                <div>
                                    <dt>Destination</dt>
                                    <dd>198.51.100.10</dd>
                                </div>
                                <div>
                                    <dt>Protocol</dt>
                                    <dd>TCP</dd>
                                </div>
                                <div>
                                    <dt>Rule</dt>
                                    <dd>{snapshot.selected.rule_id}</dd>
                                </div>
                            </dl>
                        </div>
                    </div>
                    <DecisionFeed
                        records={snapshot.feed}
                        onSelect={sim.pin}
                        selected={snapshot.selected}
                    />
                </div>
            </div>
            <p className="fine">
                Counts are measured from the deterministic repository sample;
                preview controls only change this browser illustration.
            </p>
        </div>
    );
}
