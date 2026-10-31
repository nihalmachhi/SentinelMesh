import { useCallback, useEffect, useMemo, useState } from "react";
import { flowExamples } from "../lib/simulation.js";

export function useSimulation() {
    const [mode, setMode] = useState("mixed");
    const [auto, setAuto] = useState(false);
    const [motion, setMotion] = useState(false);
    const [previewCount, setPreviewCount] = useState(0);
    const [selectedId, setSelectedId] = useState("sample-00002");
    const records = useMemo(() => flowExamples(mode), [mode]);
    const generated = useMemo(
        () =>
            Array.from({ length: previewCount }, (_, index) => ({
                ...records[index % records.length],
                flow_id: `preview-${String(index + 1).padStart(5, "0")}`,
            })),
        [previewCount, records],
    );
    const feed = [...records, ...generated].slice(-12);
    const selected =
        feed.find((record) => record.flow_id === selectedId) ?? records[0];
    const setPreviewAuto = useCallback((value) => {
        setAuto(value);
        setMotion(value);
    }, []);
    const refresh = useCallback(
        () => setPreviewCount((count) => count + 1),
        [],
    );
    const step = useCallback(() => {
        refresh();
    }, [refresh]);
    const force = useCallback((scenario) => {
        const record = flowExamples(scenario)[0];
        if (record) {
            setMode(scenario);
            setSelectedId(record.flow_id);
        }
    }, []);
    const burst = useCallback(() => setPreviewCount((count) => count + 20), []);
    const reset = useCallback(() => {
        setPreviewCount(0);
        setMode("mixed");
        setSelectedId("sample-00002");
    }, []);
    const pin = useCallback((record) => setSelectedId(record.flow_id), []);
    const follow = useCallback(
        () => setSelectedId(records[0]?.flow_id ?? ""),
        [records],
    );
    const toggleMotion = useCallback(() => {
        setMotion((value) => !value);
        setAuto((value) => !value);
    }, []);
    useEffect(() => {
        if (!auto || !motion) return undefined;
        const timer = window.setInterval(refresh, 1400);
        return () => window.clearInterval(timer);
    }, [auto, motion, refresh]);
    return {
        snapshot: { feed, selected, previewCount },
        mode,
        setMode,
        auto,
        setAuto: setPreviewAuto,
        motion,
        toggleMotion,
        step,
        force,
        burst,
        reset,
        pin,
        follow,
        reason: (record) => record.rule_id,
        isReview: (record) => record.severity !== "low",
    };
}
