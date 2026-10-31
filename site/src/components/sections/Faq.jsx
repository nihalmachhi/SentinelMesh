export default function Faq() {
    const questions = [
        [
            "Does SentinelMesh capture live traffic?",
            "No. It accepts prepared flow records; live packet capture is not enabled.",
        ],
        [
            "Can it block an IP or change a network?",
            "No. Simulated approvals are audit records only and do not invoke response controls.",
        ],
        [
            "Do the rules prove malicious activity?",
            "No. They create explainable triage signals. An analyst must review the evidence and context.",
        ],
        [
            "Why do incidents require both host and time proximity?",
            "Time overlap alone can join unrelated activity. Requiring a shared host and a bounded window keeps those findings separate.",
        ],
        [
            "Does the app send telemetry to a cloud service?",
            "The default workflow is local and offline. Optional LLM support is disabled unless explicitly configured.",
        ],
        [
            "What does the sample measurement mean?",
            "It describes this repository's generated fixture only; it does not estimate real-world accuracy.",
        ],
    ];
    return (
        <section className="sec wrap" id="faq">
            <div className="center">
                <h2>
                    Any{" "}
                    <i className="tile c-pk">
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path d="M9.5 9a2.5 2.5 0 115 0c0 2-2.5 2-2.5 4M12 17.5v.5" />
                        </svg>
                    </i>{" "}
                    <span className="d2">questions?</span>
                </h2>
            </div>
            <div className="faq">
                {questions.map(([question, answer]) => (
                    <details key={question}>
                        <summary>{question}</summary>
                        <p>{answer}</p>
                    </details>
                ))}
            </div>
        </section>
    );
}
