import { useState } from "react";
import { scrollToId } from "../../lib/dom.js";

const STEPS = [
    {
        id: "env",
        number: "1",
        title: "Create an environment",
        text: "python -m venv .venv",
        note: "Activate it with .venv\Scripts\Activate.ps1 on Windows, or source .venv/bin/activate on macOS/Linux.",
    },
    {
        id: "install",
        number: "2",
        title: "Install and generate the sample",
        text: 'python -m pip install -e ".[dev]"',
        note: "Then run: python scripts/generate_sample_data.py",
    },
    {
        id: "run",
        number: "3",
        title: "Analyze and open the dashboard",
        text: "python -m sentinelmesh analyze",
        note: "Run python -m sentinelmesh serve, then open http://127.0.0.1:8000. The local bearer token is printed in the terminal.",
    },
];

function CodeRow({ step }) {
    const [label, setLabel] = useState("Copy");
    async function copy() {
        try {
            await navigator.clipboard.writeText(step.text);
            setLabel("Copied");
        } catch {
            setLabel("Copy unavailable");
        }
        window.setTimeout(() => setLabel("Copy"), 1600);
    }
    return (
        <li>
            <h3>
                <b>{step.number}</b> {step.title}
            </h3>
            <div className="code">
                <code>{step.text}</code>
                <button type="button" onClick={copy}>
                    {label}
                </button>
            </div>
            <p>{step.note}</p>
        </li>
    );
}

export default function Start() {
    return (
        <section className="sec wrap" id="start">
            <div className="center">
                <h2>
                    Running in{" "}
                    <span className="d2">
                        <i className="tile c-k">
                            <svg viewBox="0 0 24 24" aria-hidden="true">
                                <path d="M5 8l4 4-4 4M12 17h7" />
                            </svg>
                        </i>{" "}
                        command.
                    </span>
                </h2>
                <p className="lede">
                    Python 3.11 or newer. The core runtime uses only the
                    standard library.
                </p>
            </div>
            <div className="stage" style={{ marginTop: 40 }}>
                <div className="ui" style={{ padding: 12 }}>
                    <ol className="steps">
                        {STEPS.map((step) => (
                            <CodeRow key={step.id} step={step} />
                        ))}
                    </ol>
                </div>
            </div>
            <p className="center" style={{ marginTop: 22 }}>
                <button
                    className="link"
                    type="button"
                    onClick={() => scrollToId("demo")}
                >
                    Open the synthetic preview →
                </button>
            </p>
        </section>
    );
}
