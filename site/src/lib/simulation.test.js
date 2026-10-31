import { describe, expect, it } from "vitest";
import { flowExamples } from "./simulation.js";

describe("seeded flow preview", () => {
    it("uses real sample IDs and validated flow shapes", () => {
        const flows = flowExamples();
        expect(flows.map((flow) => flow.flow_id)).toContain("sample-00002");
        expect(
            flows.every(
                (flow) =>
                    flow.src_ip && flow.dst_ip && flow.timestamp.endsWith("Z"),
            ),
        ).toBe(true);
    });

    it("shows the configured high-egress example", () => {
        expect(flowExamples("high egress")[0].rule_id).toBe("high_egress_rate");
    });
});
