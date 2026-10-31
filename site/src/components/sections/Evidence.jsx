import Inspector from "../simulator/Inspector.jsx";

export default function Evidence({ sim }) {
    return (
        <section className="sec wrap" id="evidence">
            <div className="split">
                <div className="stage" style={{ marginTop: 0 }}>
                    <Inspector sim={sim} />
                </div>
                <div>
                    <h2>
                        Every finding comes{" "}
                        <span className="d2">with evidence.</span>
                    </h2>
                    <p className="lede">
                        The selected flow, observed rule features, and
                        contextual ATT&amp;CK note stay together so an analyst
                        can check why the signal appeared.
                    </p>
                    <dl className="facts">
                        <div>
                            <dt>Flow evidence</dt>
                            <dd>
                                Finding records retain the IDs of the exact
                                source flows used by each detector.
                            </dd>
                        </div>
                        <div>
                            <dt>Observed features</dt>
                            <dd>
                                Rule-specific values—such as destination ports,
                                byte rate, and event window—are shown with the
                                signal.
                            </dd>
                        </div>
                        <div>
                            <dt>ATT&amp;CK context</dt>
                            <dd>
                                Technique mappings are candidates for analyst
                                context; flow metadata does not prove intent.
                            </dd>
                        </div>
                    </dl>
                    <div className="codes">
                        <button
                            className="btn btn-dark btn-sm"
                            type="button"
                            onClick={() => sim.force("port scan")}
                        >
                            Inspect port diversity
                        </button>
                        <button
                            className="btn btn-ghost btn-sm"
                            type="button"
                            onClick={() => sim.force("high egress")}
                        >
                            Inspect high egress
                        </button>
                        <button
                            className="btn btn-ghost btn-sm"
                            type="button"
                            onClick={() => sim.force("beacon")}
                        >
                            Inspect periodic flow
                        </button>
                    </div>
                </div>
            </div>
        </section>
    );
}
