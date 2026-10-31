import { useEffect, useRef } from "react";

/**
 * Fit a single line of text to its container by measuring, not by guessing a
 * viewport unit. The CSS container-query size is the no-JavaScript fallback.
 */
export function useFitText() {
    const containerRef = useRef(null);
    const textRef = useRef(null);

    useEffect(() => {
        const container = containerRef.current;
        const text = textRef.current;
        if (!container || !text) return undefined;

        const fit = () => {
            text.style.fontSize = "100px";
            const width = text.getBoundingClientRect().width;
            const available = container.clientWidth;
            if (width > 0 && available > 0) {
                const size =
                    Math.floor(((100 * available) / width) * 0.985 * 10) / 10;
                text.style.fontSize = `${size}px`;
            }
        };

        fit();
        window.addEventListener("resize", fit);
        const observer =
            typeof ResizeObserver === "function"
                ? new ResizeObserver(fit)
                : null;
        observer?.observe(container);
        if (document.fonts?.ready)
            document.fonts.ready.then(fit).catch(() => {});
        return () => {
            window.removeEventListener("resize", fit);
            observer?.disconnect();
        };
    }, []);

    return { containerRef, textRef };
}
