import Simulator from "../simulator/Simulator.jsx";
import { REPO } from "../layout/Header.jsx";

export default function Hero({ sim }) {
    return (
        <section className="hero wrap" id="top">
            <h1>
                Read network signals <span className="g">in context</span>.{" "}
                <span className="d">And keep the evidence.</span>
            </h1>
            <p className="sub">
                SentinelMesh is a local network-flow investigation lab. It
                validates prepared telemetry, surfaces explainable signals, and
                links every finding to the flows an analyst can review.
            </p>
            <div className="cta">
                <a className="btn btn-dark" href={REPO}>
                    View on GitHub
                </a>
                <a className="btn btn-ghost" href="#start">
                    Run it locally
                </a>
            </div>
            <p className="note">
                Python standard library runtime. A synthetic research prototype
                with no live capture or network actions.
            </p>
            <Simulator sim={sim} />
        </section>
    );
}
