"""Запуск поиска из терминала: python3 -m amber.evolve.cli"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..client import LLMClient
from .genome import RISK_TITLES, RISKS, STYLE_TITLES, STYLES
from .loop import search

MARK = {"new": "+", "improved": "^", "duplicate": "=", "worse": "·"}


def grid(cells: dict) -> str:
    """Печатает сетку архива: строки — риск, столбцы — стиль."""
    width = max(len(s) for s in STYLES) + 1
    head = " " * 16 + "".join(s[:width - 1].ljust(width) for s in STYLES)
    lines = [head]
    for risk in RISKS:
        row = [RISK_TITLES[risk][:15].ljust(16)]
        for style in STYLES:
            c = cells.get(f"{risk}|{style}")
            if not c:
                glyph = "·"
            elif c["verdict"] == "VULNERABLE":
                glyph = "█"
            else:
                glyph = "▒"
            row.append(glyph.ljust(width))
        lines.append("".join(row))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Эволюционный поиск атак (MAP-Elites)")
    p.add_argument("--url", default="http://localhost:1234")
    p.add_argument("--model", default="local-model")
    p.add_argument("--generations", type=int, default=60)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", default="reports")
    p.add_argument("--quiet", action="store_true", help="без построчного вывода")
    args = p.parse_args(argv)

    client = LLMClient(args.url, args.model)
    if not client.ping():
        print(f"Эндпоинт {args.url} не отвечает.", file=sys.stderr)
        return 2

    print(f"Поиск против {args.model} · {args.generations} поколений · "
          f"сетка {len(RISKS)}×{len(STYLES)}\n")

    final = None
    for ev in search(client, args.generations, args.seed):
        if ev["kind"] == "done":
            final = ev
            break
        if not args.quiet:
            print(f"  {ev['step']:>3}/{ev['total']} {MARK[ev['outcome']]} "
                  f"{ev['risk']:<9} {ev['style']:<11} "
                  f"f={ev['fitness']:.2f} покрытие {ev['coverage']}/{ev['capacity']}")

    print("\n" + grid(final["cells"]))
    print(f"\n█ пробой найден   ▒ клетка занята, пробоя нет   · пусто")
    print(f"\nпокрытие: {final['coverage']}/{final['capacity']} клеток · "
          f"пробоев: {final['solved']} · отсеяно дубликатов: {final['duplicates']}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "archive.json").write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"архив: {out / 'archive.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
