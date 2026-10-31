const REPO = "https://github.com/nihalmachhi/SentinelMesh";
const BASE = import.meta.env.BASE_URL;

export default function Header({ motion, onToggleMotion }) {
    return (
        <header className="top">
            <div className="wrap">
                <a className="brand" href="#top" aria-label="SentinelMesh home">
                    <img
                        className="logo"
                        src={`${BASE}assets/readme-icon.png`}
                        alt=""
                    />
                    SentinelMesh
                </a>
                <nav className="nav" aria-label="Sections">
                    <a href="#pipeline">Pipeline</a>
                    <a href="#evidence">Evidence</a>
                    <a href="#offline">Correlation</a>
                    <a href="#results">Results</a>
                    <a href="#features">Features</a>
                    <a href="#start">Quick start</a>
                    <a href="#faq">FAQ</a>
                </nav>
                <div className="tools">
                    <button
                        className="btn btn-ghost btn-sm pause"
                        type="button"
                        aria-pressed={!motion}
                        onClick={onToggleMotion}
                    >
                        <svg
                            width="12"
                            height="12"
                            viewBox="0 0 12 12"
                            fill="currentColor"
                            aria-hidden="true"
                        >
                            <rect x="2" y="1" width="3" height="10" rx="1" />
                            <rect x="7" y="1" width="3" height="10" rx="1" />
                        </svg>
                        <span className="lbl">
                            {motion ? "Pause animations" : "Play animations"}
                        </span>
                    </button>
                    <a className="btn btn-dark btn-sm" href={REPO}>
                        GitHub
                    </a>
                </div>
            </div>
        </header>
    );
}

export { REPO };
