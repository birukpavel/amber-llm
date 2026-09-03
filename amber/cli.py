"""Запуск из терминала: python3 -m amber.cli

Вывод — главная поверхность инструмента: его скриншотят и пересылают.
Поэтому здесь печатается ровно две вещи: находки и границы того,
чего сканер не видит.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from pathlib import Path

from .client import LLMClient, is_local
from .detectors import INCONCLUSIVE, VULNERABLE
from .probes import CATEGORY_TITLES, PROBES
from .report import write_json, write_markdown
from .runner import Result, scan, summarize

# Янтарный, а не красный: срабатывание — это указатель «смотри сюда»,
# а не приговор «сломано, чините».
HIT = "\033[38;5;214m"
DIM = "\033[38;5;245m"
RESET = "\033[0m"

MARK = {
    VULNERABLE: ("●", "сработал    "),
    "SAFE": ("○", "не сработал "),
    INCONCLUSIVE: ("◍", "нет данных  "),
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
WIDTH = 62


def _paint(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text


def _print_live(result: Result) -> None:
    glyph, label = MARK[result.verdict]
    color = HIT if result.verdict == VULNERABLE else DIM
    line = _paint(f"{glyph} {label}", color)
    reason = result.effect if result.verdict == VULNERABLE else result.reason
    print(f"  {result.probe_id:<8} {line} {reason}")


def _field(name: str, text: str) -> None:
    """Поле с висячим отступом: имя слева, текст колонкой справа."""
    body = textwrap.wrap(text.strip(), width=WIDTH - 14) or [""]
    print(f"  {name:<11} {body[0]}")
    for line in body[1:]:
        print(f"  {'':<11} {line}")


def _print_finding(result: Result) -> None:
    """Одна находка подробно. Пять развёрнутых блоков никто не читает."""
    rule = "─" * WIDTH
    title = CATEGORY_TITLES.get(result.category, result.category)
    print(f"\n  {_paint(rule, DIM)}")
    print(f"  {_paint(result.probe_id, HIT)}  {title}  {result.owasp} · {result.severity}\n")
    _field("отправлено", result.prompt)
    print()
    _field("получено", result.response[:400] or "«пусто»")
    print()
    _field("детектор", result.reason)
    print()
    for index, line in enumerate(textwrap.wrap(result.next_check, width=WIDTH - 4)):
        print(f"  {'→' if index == 0 else ' '} {line}")
    print(f"  {_paint(rule, DIM)}")


def _print_manual_checks() -> None:
    print("\n  Три проверки, которые сканер сделать не может\n")
    for number, text in enumerate(
        (
            "Спросите систему, как она устроена, и сверьте ответ с тем, "
            "что вы про неё знаете.",
            "Найдите в конфиге все пороги. Не «разумное ли значение», а "
            "сколько раз за неделю каждый из них сработал.",
            "Откройте тесты и прочитайте, что они утверждают. «Функция "
            "вернула список» не проверяет ничего.",
        ),
        start=1,
    ):
        body = textwrap.wrap(text, width=WIDTH - 5)
        print(f"  {number}. {body[0]}")
        for line in body[1:]:
            print(f"     {line}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="amber — подсвечивает места, где ломается ассистент с LLM")
    parser.add_argument("--url", default="http://localhost:1234", help="базовый URL эндпоинта")
    parser.add_argument("--model", default="local-model", help="идентификатор модели")
    parser.add_argument(
        "--api-key",
        default=None,
        help="ключ; безопаснее задать переменной AMBER_API_KEY — "
             "аргумент виден в ps и остаётся в истории shell",
    )
    parser.add_argument("--category", action="append", help="ограничить категориями (можно несколько)")
    parser.add_argument("--out", default="reports", help="каталог для отчётов")
    args = parser.parse_args(argv)

    client = LLMClient(args.url, args.model, api_key=args.api_key)
    problem = client.check()
    if problem:
        print(f"Эндпоинт {args.url} недоступен: {problem}", file=sys.stderr)
        return 2

    probes = PROBES
    if args.category:
        probes = [p for p in PROBES if p.category in args.category]
        if not probes:
            print("По заданным категориям пробников нет.", file=sys.stderr)
            return 2

    print(_paint("\n  подсвечивает места, не выносит вердикт о безопасности", DIM))
    print(_paint("  не проверяет: многоходовые атаки · RAG-слой и фильтры · "
                 "смысловые утечки", DIM))
    print(f"\n  {len(probes)} пробников · {args.model} · {args.url}")
    if not is_local(args.url):
        print(_paint("  внешний API: вы платите за эти запросы, а индекс прогона "
                     "сравним", DIM))
        print(_paint("  только с прогонами того же дня — провайдер меняет версию "
                     "модели молча", DIM))
    print()

    results = scan(client, probes, on_result=_print_live)
    summary = summarize(results, args.model, args.url)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_markdown(summary, out / "report.md")
    write_json(summary, out / "report.json")

    hits = [r for r in results if r.verdict == VULNERABLE]
    print(f"\n  Сработало: {len(hits)} из {len(results)}")

    if hits:
        # В терминал — самую критичную, остальные в отчёт.
        _print_finding(min(hits, key=lambda r: SEVERITY_ORDER[r.severity]))
        if len(hits) > 1:
            print(f"\n  Остальные {len(hits) - 1} — в отчёте.")
    else:
        print(f"  Не сработали эти {len(results)}. Это не значит, "
              "что система устойчива.")

    _print_manual_checks()

    print(f"\n  Отчёт: {out / 'report.md'} · {out / 'report.json'}")
    print(_paint(f"  Индекс прогона: {summary['robustness_score']} — для сравнения "
                 "прогонов между собой,", DIM))
    print(_paint("  это не оценка безопасности.\n", DIM))
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
