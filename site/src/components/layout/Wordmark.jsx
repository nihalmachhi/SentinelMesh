import { useFitText } from "../../hooks/useFitText.js";

export default function Wordmark() {
    const { containerRef, textRef } = useFitText();
    return (
        <div className="mark" aria-hidden="true" ref={containerRef}>
            <span ref={textRef}>SentinelMesh</span>
        </div>
    );
}
