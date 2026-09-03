"""Прогон пробников и сбор результатов."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator

from .client import LLMClient, LLMError
from .detectors import DETECTORS, INCONCLUSIVE
from .probes import PROBES, SYSTEM_PROMPT, Probe

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Result:
    probe_id: str
    category: str
    severity: str
    verdict: str
    reason: str
    rationale: str
    owasp: str
    effect: str
    next_check: str
    prompt: str
    response: str
    latency_s: float
    tags: list[str]


def _run_one(client: LLMClient, probe: Probe) -> Result:
    detector = DETECTORS[probe.detector]
    try:
        reply = client.chat(SYSTEM_PROMPT, probe.prompt)
        text, latency = reply.text, reply.latency_s
    except LLMError as exc:
        return Result(
            probe_id=probe.id,
            category=probe.category,
            severity=probe.severity,
            verdict=INCONCLUSIVE,
            reason=f"ошибка запроса: {exc}",
            rationale=probe.rationale,
            owasp=probe.owasp,
            effect=probe.effect,
            next_check=probe.next_check,
            prompt=probe.prompt,
            response="",
            latency_s=0.0,
            tags=probe.tags,
        )

    if probe.detector_arg is None:
        verdict, reason = detector(text)
    else:
        verdict, reason = detector(text, probe.detector_arg)

    return Result(
        probe_id=probe.id,
        category=probe.category,
        severity=probe.severity,
        verdict=verdict,
        reason=reason,
        rationale=probe.rationale,
        owasp=probe.owasp,
        effect=probe.effect,
        next_check=probe.next_check,
        prompt=probe.prompt,
        response=text,
        latency_s=latency,
        tags=probe.tags,
    )


def scan(
    client: LLMClient,
    probes: Iterable[Probe] = PROBES,
    on_result: Callable[[Result], None] | None = None,
) -> list[Result]:
    """Прогоняет пробники последовательно (модель обычно обслуживает один запрос)."""
    results: list[Result] = []
    for probe in probes:
        result = _run_one(client, probe)
        results.append(result)
        if on_result:
            on_result(result)
    return results


def iter_scan(client: LLMClient, probes: Iterable[Probe] = PROBES) -> Iterator[Result]:
    """То же, но потоком — для живого вывода в интерфейсе."""
    for probe in probes:
        yield _run_one(client, probe)


def summarize(results: list[Result], model: str, endpoint: str) -> dict:
    vulnerable = [r for r in results if r.verdict == "VULNERABLE"]
    max_score = sum(SEVERITY_WEIGHT[r.severity] for r in results)
    lost = sum(SEVERITY_WEIGHT[r.severity] for r in vulnerable)
    robustness = round(100 * (max_score - lost) / max_score) if max_score else 0

    by_category: dict[str, dict[str, int]] = {}
    for result in results:
        bucket = by_category.setdefault(
            result.category, {"total": 0, "vulnerable": 0, "safe": 0, "inconclusive": 0}
        )
        bucket["total"] += 1
        bucket[result.verdict.lower()] += 1

    by_owasp: dict[str, dict[str, int]] = {}
    for result in results:
        bucket = by_owasp.setdefault(result.owasp, {"total": 0, "vulnerable": 0})
        bucket["total"] += 1
        if result.verdict == "VULNERABLE":
            bucket["vulnerable"] += 1

    return {
        "model": model,
        "endpoint": endpoint,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(results),
        "vulnerable": len(vulnerable),
        "safe": sum(1 for r in results if r.verdict == "SAFE"),
        "inconclusive": sum(1 for r in results if r.verdict == INCONCLUSIVE),
        "robustness_score": robustness,
        "by_category": by_category,
        "by_owasp": by_owasp,
        "results": [asdict(r) for r in results],
    }
