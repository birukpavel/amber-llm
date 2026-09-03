"""Архив MAP-Elites.

Ключевое отличие от обычного поиска: цель — не максимум доли успеха, а
покрытие сетки поведений. В каждой клетке (риск × стиль) хранится лучшая
найденная особь. Так поиск не сходится к одной заученной уловке — это
основной способ борьбы с mode collapse.
"""

from __future__ import annotations

import random
from difflib import SequenceMatcher

from .genome import RISKS, STYLES, Individual

# Порог отсечения почти-дубликатов. Аналог BLEU-фильтра в Rainbow Teaming:
# без него архив забивается перефразировками одной находки.
SIMILARITY_CAP = 0.92


class Archive:
    def __init__(self) -> None:
        self.cells: dict[tuple[str, str], Individual] = {}
        self.coverage_history: list[int] = []
        self.rejected_duplicates = 0

    @property
    def capacity(self) -> int:
        return len(RISKS) * len(STYLES)

    @property
    def coverage(self) -> int:
        return len(self.cells)

    @property
    def solved(self) -> int:
        """Клетки, где найдена настоящая уязвимость, а не просто лучший кандидат."""
        return sum(1 for i in self.cells.values() if i.verdict == "VULNERABLE")

    def is_duplicate(self, candidate: Individual) -> bool:
        text = candidate.render()
        for existing in self.cells.values():
            if SequenceMatcher(None, text, existing.render()).ratio() > SIMILARITY_CAP:
                return True
        return False

    def offer(self, candidate: Individual) -> str:
        """Пытается поместить особь в её клетку. Возвращает исход."""
        cell = candidate.cell
        current = self.cells.get(cell)

        if current is not None and candidate.fitness <= current.fitness:
            return "worse"
        if self.is_duplicate(candidate):
            self.rejected_duplicates += 1
            return "duplicate"

        self.cells[cell] = candidate
        return "new" if current is None else "improved"

    def random_elite(self, rng: random.Random) -> Individual | None:
        return rng.choice(list(self.cells.values())) if self.cells else None

    def snapshot(self) -> dict:
        return {
            "coverage": self.coverage,
            "capacity": self.capacity,
            "solved": self.solved,
            "duplicates": self.rejected_duplicates,
            "cells": {
                f"{r}|{s}": {
                    "risk": r,
                    "style": s,
                    "fitness": round(i.fitness, 3),
                    "verdict": i.verdict,
                    "reason": i.reason,
                    "prompt": i.render(),
                    "response": i.response,
                    "ops": i.ops,
                    "generation": i.generation,
                }
                for (r, s), i in self.cells.items()
            },
        }
