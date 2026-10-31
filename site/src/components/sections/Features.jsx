export default function Features() {
    const items = [
        [
            "c-p",
            "Typed flow model",
            "Validated network metadata with timezone-aware event timestamps.",
        ],
        [
            "c-y",
            "Five explainable rules",
            "Port diversity, sensitive services, egress rate, periodicity, and earlier-host baselines.",
        ],
        [
            "c-o",
            "Evidence-linked incidents",
            "Shared-host correlation within a configurable time window.",
        ],
        [
            "c-g",
            "Local JSON API",
            "Loopback-only server, per-run bearer token, request limits, and strict security headers.",
        ],
        [
            "c-c",
            "Append-only audit",
            "SQLite records analyst actions in a hash-chained audit trail.",
        ],
        [
            "c-r",
            "Optional extras",
            "Graph summaries and Isolation Forest stay outside the standard-library runtime.",
        ],
    ];
    return (
        <section className="sec wrap" id="features">
            <div className="center">
                <h2>
                    Small modules. <span className="d2">Clear boundaries.</span>
                </h2>
                <p className="lede">
                    The project keeps ingestion, rule detection, correlation,
                    persistence, and analyst review in separate, inspectable
                    parts.
                </p>
            </div>
            <div className="bento">
                {items.map(([color, title, text], index) => (
                    <article
                        className={`bc ${index === 0 || index === 3 ? "s2" : ""}`}
                        key={title}
                    >
                        <span className={`ic ${color}`}>
                            <svg viewBox="0 0 24 24" aria-hidden="true">
                                <path d="M5 12h14M12 5v14" />
                            </svg>
                        </span>
                        <h3>{title}</h3>
                        <p>{text}</p>
                        <div className="bv">
                            <div className="chips">
                                <span>
                                    {
                                        [
                                            "Python 3.11+",
                                            "five rules",
                                            "host + time",
                                            "127.0.0.1",
                                            "SQLite",
                                            "optional",
                                        ][index]
                                    }
                                </span>
                            </div>
                        </div>
                    </article>
                ))}
            </div>
        </section>
    );
}
