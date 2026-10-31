import { scrollToId } from "../../lib/dom.js";

export default function Pipeline({ sim }) {
    return (
        <section className="sec wrap" id="pipeline">
            <div className="center">
                <h2>
                    Four steps.{" "}
                    <span className="d2">
                        One{" "}
                        <i className="tile c-g">
                            <svg viewBox="0 0 24 24" aria-hidden="true">
                                <path d="M5 12.5l4.5 4.5L19 7" />
                            </svg>
                        </i>{" "}
                        evidence trail.
                    </span>
                </h2>
                <p className="lede">
                    Prepared flows are validated, checked by explainable rules,
                    correlated by host and time, then reviewed by an analyst.
                </p>
            </div>
            <div className="cards">
                <article className="card">
                    <span className="ic c-p">
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M4 7h16M4 12h16M4 17h16" />
                        </svg>
                    </span>
                    <h3>1. Validate</h3>
                    <p>
                        Bounded JSON, Zeek, or normalized NetFlow records become
                        typed flows with UTC timestamps and explicit field
                        checks.
                    </p>
                    <div className="viz">
                        <div className="chips">
                            <span>JSON</span>
                            <span>Zeek</span>
                            <span>NetFlow CSV</span>
                            <span>UTC</span>
                        </div>
                        <div className="leg">
                            Metadata only · no packet capture
                        </div>
                    </div>
                    <button
                        className="link"
                        type="button"
                        onClick={() => scrollToId("demo")}
                    >
                        Inspect sample flows →
                    </button>
                </article>
                <article className="card">
                    <span className="ic c-y">
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z" />
                        </svg>
                    </span>
                    <h3>2. Explain signals</h3>
                    <p>
                        Five deterministic rules flag port diversity, sensitive
                        services, high egress, periodic connections, and
                        host-baseline outliers.
                    </p>
                    <div className="viz">
                        <div className="chips">
                            <span>rule id</span>
                            <span>severity</span>
                            <span>evidence IDs</span>
                            <span>features</span>
                        </div>
                        <div className="leg">Review signal · not a verdict</div>
                    </div>
                    <button
                        className="link"
                        type="button"
                        onClick={() => sim.force("high egress")}
                    >
                        Inspect a high-egress example →
                    </button>
                </article>
                <article className="card">
                    <span className="ic c-o">
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                            <circle cx="6" cy="12" r="2" />
                            <circle cx="18" cy="6" r="2" />
                            <circle cx="18" cy="18" r="2" />
                            <path d="M8 11l8-4M8 13l8 4" />
                        </svg>
                    </span>
                    <h3>3. Correlate + review</h3>
                    <p>
                        Findings join only across a shared host and nearby event
                        window. Analysts inspect linked records in the local
                        dashboard.
                    </p>
                    <div className="viz">
                        <div className="chips">
                            <span>shared host</span>
                            <span>300 seconds</span>
                            <span>stable incident ID</span>
                        </div>
                        <div className="leg">Loopback API · human review</div>
                    </div>
                    <button
                        className="link"
                        type="button"
                        onClick={() => scrollToId("evidence")}
                    >
                        See linked evidence →
                    </button>
                </article>
            </div>
        </section>
    );
}
