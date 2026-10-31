export default function Scope() {
    return (
        <section className="sec wrap">
            <div className="center">
                <h2>
                    Built to{" "}
                    <span className="d2">
                        <i className="tile c-o">
                            <svg viewBox="0 0 24 24" aria-hidden="true">
                                <path d="M9 18h6M10 21h4M12 3a6 6 0 00-3.5 10.9c.6.5 1 1.2 1 2.1h5c0-.9.4-1.6 1-2.1A6 6 0 0012 3z" />
                            </svg>
                        </i>{" "}
                        teach.
                    </span>
                </h2>
                <p className="lede">
                    A safe, local environment for learning evidence-based
                    network-flow triage.
                </p>
            </div>
            <div className="two">
                <div className="card">
                    <span className="ic c-g">
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M5 12.5l4.5 4.5L19 7" />
                        </svg>
                    </span>
                    <h3>In scope</h3>
                    <ul>
                        <li>Prepared synthetic and normalized flow metadata</li>
                        <li>Explainable rule-based triage signals</li>
                        <li>
                            Evidence correlation with bounded host and time
                            rules
                        </li>
                        <li>Local dashboard, JSON API, and audit review</li>
                        <li>Reproducible offline sample evaluation</li>
                    </ul>
                </div>
                <div className="card">
                    <span className="ic c-r">
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M6 6l12 12M18 6L6 18" />
                        </svg>
                    </span>
                    <h3>Out of scope</h3>
                    <ul>
                        <li>Live packet capture or network scanning</li>
                        <li>Blocking, containment, or real response actions</li>
                        <li>Real customer data or verified attack labels</li>
                        <li>Internet-facing server deployment</li>
                        <li>Claims of production detection accuracy</li>
                    </ul>
                </div>
            </div>
        </section>
    );
}
