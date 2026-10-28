"""Chronological evaluation of rule and optional anomaly model scores."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from sentinelmesh.core.models import Flow
from sentinelmesh.detection.rules import detect
from sentinelmesh.ingest.datasets import LabeledFlowDataset


def _metrics(labels: list[int], scores: list[float], threshold: float) -> dict[str, Any]:
    predicted = [score >= threshold for score in scores]
    true_positive = sum(
        label == 1 and guess for label, guess in zip(labels, predicted, strict=True)
    )
    false_positive = sum(
        label == 0 and guess for label, guess in zip(labels, predicted, strict=True)
    )
    false_negative = sum(
        label == 1 and not guess for label, guess in zip(labels, predicted, strict=True)
    )
    precision = (
        true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    positives = sum(labels)
    average_precision = 0.0
    if positives:
        ranked = sorted(zip(scores, labels, strict=True), key=lambda item: item[0], reverse=True)
        hits = 0
        precision_sum = 0.0
        for rank, (_, label) in enumerate(ranked, start=1):
            if label:
                hits += 1
                precision_sum += hits / rank
        average_precision = precision_sum / positives
    return {
        "threshold": threshold,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "average_precision_pr_auc": round(average_precision, 6),
        "true_positives": true_positive,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "positive_test_rows": positives,
    }


def _rule_scores(flows: list[Flow]) -> list[float]:
    indices = {flow.flow_id: index for index, flow in enumerate(flows)}
    scores = [0.0] * len(flows)
    for finding in detect(flows):
        for evidence_id in finding.evidence_ids:
            index = indices.get(evidence_id)
            if index is not None:
                scores[index] = max(scores[index], finding.score)
    return scores


def _isolation_forest_scores(
    training: list[Flow], testing: list[Flow], contamination: float, seed: int
) -> tuple[list[float], float]:
    try:
        from sklearn.ensemble import IsolationForest  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("install the optional ML extra: pip install -e '.[ml]'") from exc

    def features(flow: Flow) -> list[float]:
        return [
            math.log1p(flow.bytes_sent),
            math.log1p(flow.duration_ms),
            math.log1p(flow.packets),
            float(flow.src_port),
            float(flow.dst_port),
            float({"TCP": 6, "UDP": 17, "ICMP": 1}[flow.protocol]),
        ]

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=seed,
        n_jobs=1,
    )
    model.fit([features(flow) for flow in training])
    train_anomaly_scores = [
        -float(value) for value in model.score_samples([features(f) for f in training])
    ]
    threshold_index = max(
        0, min(len(training) - 1, math.ceil((1 - contamination) * len(training)) - 1)
    )
    threshold = sorted(train_anomaly_scores)[threshold_index]
    test_scores = [-float(value) for value in model.score_samples([features(f) for f in testing])]
    return test_scores, threshold


def evaluate_dataset(
    dataset: LabeledFlowDataset,
    *,
    model: str = "rules",
    threshold: float = 0.5,
    contamination: float = 0.01,
    seed: int = 41,
) -> dict[str, Any]:
    """Evaluate the last 20% chronologically; all rows remain outside the repository."""
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be in [0, 1]")
    ordered = sorted(
        zip(dataset.flows, dataset.labels, strict=True), key=lambda row: row[0].timestamp
    )
    if len(ordered) < 5:
        raise ValueError("at least five labeled rows are required for an 80/20 chronological split")
    split = int(len(ordered) * 0.8)
    if split < 1 or split >= len(ordered):
        raise ValueError("dataset cannot be split into non-empty chronological partitions")
    train_flows = [row[0] for row in ordered[:split]]
    test_flows = [row[0] for row in ordered[split:]]
    test_labels = [row[1] for row in ordered[split:]]
    if model == "rules":
        all_scores = _rule_scores([row[0] for row in ordered])
        test_scores = all_scores[split:]
        used_threshold = threshold
    elif model == "isolation-forest":
        if not 0 < contamination <= 0.5:
            raise ValueError("contamination must be in (0, 0.5]")
        test_scores, used_threshold = _isolation_forest_scores(
            train_flows, test_flows, contamination, seed
        )
    else:
        raise ValueError("model must be rules or isolation-forest")
    result = _metrics(test_labels, test_scores, used_threshold)
    first = datetime.fromisoformat(test_flows[0].timestamp).astimezone(UTC)
    last = datetime.fromisoformat(test_flows[-1].timestamp).astimezone(UTC)
    span_days = max((last - first).total_seconds() / 86_400, 1 / 86_400)
    result.update(
        {
            "dataset": dataset.name,
            "data_kind": "public labeled research dataset",
            "model": model,
            "rows": len(ordered),
            "train_rows": len(train_flows),
            "test_rows": len(test_flows),
            "split": "chronological 80/20",
            "false_alerts_per_day": round(result["false_positives"] / span_days, 6),
            "test_period_start": first.isoformat(),
            "test_period_end": last.isoformat(),
            "caveat": "Dataset-specific result only; do not combine with the synthetic demo sample.",
        }
    )
    return result
