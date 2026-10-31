const results = [
    ["600", "synthetic input flows", "Seed 41 · generated locally"],
    ["17", "findings", "Measured pipeline output"],
    ["4", "incidents", "After host + time correlation"],
];

export default function Results() {
    return (
        <section className="sec wrap" id="results">
            <div className="center">
                <h2>
                    Measured on the <span className="d2">seeded sample.</span>
                </h2>
                <p className="lede">
                    The repository generator and benchmark script produce a
                    repeatable local run. These are fixture counts, not
                    real-world detection claims.
                </p>
            </div>
            <div className="cards">
                {results.map(([value, title, description], index) => (
                    <article className="card" key={title}>
                        <span className={`ic ${["c-c", "c-y", "c-g"][index]}`}>
                            <svg viewBox="0 0 24 24" aria-hidden="true">
                                <path d="M5 20V10M12 20V4M19 20v-7" />
                            </svg>
                        </span>
                        <h3>
                            {value} {title}
                        </h3>
                        <p>{description}</p>
                        <div className="viz">
                            <div className="leg">
                                Python 3.13.7 · Windows · five benchmark repeats
                            </div>
                        </div>
                    </article>
                ))}
            </div>
            <p
                className="fine center"
                style={{ maxWidth: "72ch", margin: "18px auto 0" }}
            >
                Local stage medians: parsing 12.708 ms, detection 2.259 ms,
                correlation 0.319 ms. Timings exclude SQLite and HTTP and are
                machine-specific. The synthetic fixture cannot estimate real
                false-positive rates or operational recall.
            </p>
        </section>
    );
}
