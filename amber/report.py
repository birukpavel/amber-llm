"""Отчёты: Markdown для чтения, JSON для сравнения прогонов.

Markdown устроен под пересылку: человек, не запускавший сканер, читает
первые двадцать строк и должен понять находки без пояснений.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .client import is_local
from .probes import CATEGORY_TITLES

MANUAL_CHECKS = [
    "Спросите систему, как она устроена, и сверьте ответ.",
    "Найдите пороги в конфиге — срабатывал ли хоть один за неделю?",
    "Прочитайте, что утверждают ваши тесты.",
]


def _plural(count: int, one: str, few: str, many: str) -> str:
    """Русское согласование: 1 пробник, 2 пробника, 5 пробников."""
    tail_100, tail_10 = count % 100, count % 10
    if 11 <= tail_100 <= 14:
        return many
    if tail_10 == 1:
        return one
    if 2 <= tail_10 <= 4:
        return few
    return many


def write_json(summary: dict, path: Path) -> None:
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def _when(timestamp: str) -> str:
    try:
        return datetime.fromisoformat(timestamp).strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return timestamp


def render_markdown(summary: dict) -> str:
    results = summary["results"]
    hits = [r for r in results if r["verdict"] == "VULNERABLE"]
    misses = [r for r in results if r["verdict"] == "SAFE"]
    unknown = [r for r in results if r["verdict"] == "INCONCLUSIVE"]

    lines = [
        f"# amber · {summary['model']} · {_when(summary['timestamp'])}",
        "",
        f"**Сработало: {len(hits)} из {summary['total']}.** "
        f"Индекс прогона {summary['robustness_score']} (сравнивать с прошлыми "
        "прогонами этой же системы; это не оценка безопасности).",
        "",
        f"Эндпоинт: `{summary['endpoint']}`",
        f"Системный промпт: {summary.get('prompt_source', 'встроенный учебный')}",
        "",
    ]

    if str(summary.get("prompt_source", "")).startswith("ваш"):
        lines += [
            "> Проверялся ваш системный промпт. Индекс сравним только с прогонами "
            "этого же промпта: измеряется прочность вашего ограничения, а не "
            "учебного.",
            "",
        ]

    if not is_local(summary["endpoint"]):
        lines += [
            "> Прогон против внешнего API. Индекс сравним только с прогонами того же "
            "дня: провайдер меняет версию модели под тем же именем, а батчинг делает "
            "ответы недетерминированными даже при `temperature=0`.",
            "",
        ]

    if hits:
        lines += [
            "## Что сработало",
            "",
            "| Пробник | Что произошло | OWASP |",
            "| --- | --- | --- |",
        ]
        lines += [
            f"| `{r['probe_id']}` | {r['effect']} | {r['owasp']} |" for r in hits
        ]
    else:
        lines += [
            "## Что сработало",
            "",
            "Ничего. Это значит только то, что не сработали эти "
            f"{summary['total']} "
            f"{_plural(summary['total'], 'пробник', 'пробника', 'пробников')}, "
            "— см. «Чего сканер не делает».",
        ]

    if misses:
        ids = ", ".join(r["probe_id"] for r in misses)
        lines += [
            "",
            "## Что не сработало",
            "",
            f"{ids} — эти {len(misses)} "
            f"{_plural(len(misses), 'пробник', 'пробника', 'пробников')} "
            "ограничения не пробили. "
            "Это не значит, что система устойчива: см. «Чего сканер не делает».",
        ]

    if unknown:
        ids = ", ".join(f"{r['probe_id']} ({r['reason']})" for r in unknown)
        lines += ["", "## Нет данных", "", f"{ids}."]

    for result in hits:
        title = CATEGORY_TITLES.get(result["category"], result["category"])
        lines += [
            "",
            f"## {result['probe_id']} — подробно",
            "",
            f"{title} · {result['owasp']} · {result['severity']}",
            "",
            "**Отправлено**",
            "",
            "```",
            result["prompt"],
            "```",
            "",
            "**Получено**",
            "",
            "```",
            result["response"][:1500],
            "```",
            "",
            f"**Вердикт детектора:** {result['reason']}.",
            "",
            f"**Что проверить у себя:** {result['next_check']}",
        ]

    lines += [
        "",
        "## Что сделать дальше руками",
        "",
        f"Сканер проверил {summary['total']} "
        f"{_plural(summary['total'], 'гипотезу', 'гипотезы', 'гипотез')}. "
        "Эти три проверки он сделать "
        "не может, а находят они больше.",
        "",
    ]
    lines += [f"{i}. {text}" for i, text in enumerate(MANUAL_CHECKS, start=1)]
    lines.append("")

    return "\n".join(lines) + "\n"


def write_markdown(summary: dict, path: Path) -> None:
    path.write_text(render_markdown(summary), encoding="utf-8")
