import { REPO } from "./Header.jsx";
const BASE = import.meta.env.BASE_URL;

export default function Footer() {
    return (
        <footer className="foot">
            <div className="wrap">
                <div className="foot-panel">
                    <div className="foot-top">
                        <div>
                            <a className="brand" href="#top">
                                <img
                                    className="logo"
                                    src={`${BASE}assets/readme-icon.png`}
                                    alt=""
                                />
                                SentinelMesh
                            </a>
                            <p>
                                A local, evidence-first defensive network-flow
                                investigation lab.
                            </p>
                        </div>
                        <nav aria-label="Project">
                            <h4>Project</h4>
                            <ul>
                                <li>
                                    <a href="#pipeline">Pipeline</a>
                                </li>
                                <li>
                                    <a href="#evidence">Evidence</a>
                                </li>
                                <li>
                                    <a href="#results">Measured sample</a>
                                </li>
                                <li>
                                    <a href="#features">Features</a>
                                </li>
                                <li>
                                    <a href="#start">Quick start</a>
                                </li>
                            </ul>
                        </nav>
                        <nav aria-label="Documentation">
                            <h4>Docs</h4>
                            <ul>
                                <li>
                                    <a
                                        href={`${REPO}/blob/main/docs/architecture.md`}
                                    >
                                        Architecture
                                    </a>
                                </li>
                                <li>
                                    <a
                                        href={`${REPO}/blob/main/docs/detection-rules.md`}
                                    >
                                        Detection rules
                                    </a>
                                </li>
                                <li>
                                    <a href={`${REPO}/blob/main/docs/api.md`}>
                                        API
                                    </a>
                                </li>
                                <li>
                                    <a
                                        href={`${REPO}/blob/main/docs/threat-model.md`}
                                    >
                                        Threat model
                                    </a>
                                </li>
                                <li>
                                    <a
                                        href={`${REPO}/blob/main/docs/development.md`}
                                    >
                                        Development
                                    </a>
                                </li>
                            </ul>
                        </nav>
                        <nav aria-label="Source">
                            <h4>Source</h4>
                            <ul>
                                <li>
                                    <a href={REPO}>GitHub</a>
                                </li>
                                <li>
                                    <a href={`${REPO}/blob/main/SECURITY.md`}>
                                        Security policy
                                    </a>
                                </li>
                                <li>
                                    <a
                                        href={`${REPO}/blob/main/CONTRIBUTING.md`}
                                    >
                                        Contributing
                                    </a>
                                </li>
                            </ul>
                        </nav>
                    </div>
                    <div className="foot-fine">
                        <span>
                            Synthetic triage signals are not production
                            detections. The dashboard is intended to stay on
                            loopback.
                        </span>
                        <span>Python · SQLite · React</span>
                    </div>
                    <div className="mark" aria-hidden="true">
                        SentinelMesh
                    </div>
                </div>
            </div>
        </footer>
    );
}
