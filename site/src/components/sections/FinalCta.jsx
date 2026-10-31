import { scrollToId } from "../../lib/dom.js";

const REPO = "https://github.com/nihalmachhi/SentinelMesh";

export default function FinalCta() {
    return (
        <section className="wrap">
            <div className="final">
                <svg
                    viewBox="0 0 560 190"
                    role="img"
                    aria-label="Prepared network flows pass through validation and detection to evidence-linked findings for analyst review"
                >
                    <rect
                        className="nd"
                        x="6"
                        y="68"
                        width="110"
                        height="54"
                        rx="14"
                    />
                    <text x="61" y="100" textAnchor="middle">
                        flow records
                    </text>
                    <rect
                        className="px"
                        x="198"
                        y="55"
                        width="142"
                        height="80"
                        rx="18"
                    />
                    <text x="269" y="100" textAnchor="middle">
                        SentinelMesh
                    </text>
                    <rect
                        className="nd"
                        x="438"
                        y="8"
                        width="116"
                        height="46"
                        rx="14"
                    />
                    <text x="496" y="36" textAnchor="middle">
                        findings
                    </text>
                    <rect
                        className="nd"
                        x="438"
                        y="72"
                        width="116"
                        height="46"
                        rx="14"
                    />
                    <text x="496" y="100" textAnchor="middle">
                        incidents
                    </text>
                    <rect
                        className="nd"
                        x="438"
                        y="136"
                        width="116"
                        height="46"
                        rx="14"
                    />
                    <text x="496" y="164" textAnchor="middle">
                        analyst review
                    </text>
                    <path
                        className="ln"
                        d="M116 95h82M340 80c54 0 52-49 98-49M340 95h98M340 110c54 0 52 49 98 49"
                    />
                </svg>
                <h2>
                    Inspect a signal.{" "}
                    <span className="d2">Keep its evidence.</span>
                </h2>
                <div className="cta">
                    <a className="btn btn-dark" href={REPO}>
                        View on GitHub
                    </a>
                    <button
                        className="btn btn-ghost"
                        type="button"
                        onClick={() => scrollToId("demo")}
                    >
                        Back to the preview
                    </button>
                </div>
            </div>
        </section>
    );
}
