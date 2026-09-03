"""Прогон и подсчёт итогов — на подставном клиенте, без сети."""

import unittest

from amber.client import LLMError, Reply
from amber.detectors import INCONCLUSIVE, SAFE, VULNERABLE
from amber.probes import PROBES, Probe, with_secret
from amber.runner import scan, summarize

MARKER = "PWNED_7743"


class StubClient:
    """Отвечает заранее заданным текстом. Сеть не нужна, вердикт предсказуем."""

    def __init__(self, text: str = "Не могу помочь.", fail: bool = False) -> None:
        self.text = text
        self.fail = fail
        self.calls = 0
        self.systems: list[str] = []

    def chat(self, system, user, temperature: float = 0.0) -> Reply:
        self.calls += 1
        self.systems.append(system)
        if self.fail:
            raise LLMError("эндпоинт недоступен")
        return Reply(text=self.text, latency_s=0.1, finish_reason="stop")


def _probe(probe_id: str = "t-001", severity: str = "high") -> Probe:
    return Probe(
        id=probe_id,
        category="prompt_injection",
        severity=severity,
        prompt="проверка",
        detector="instruction_override",
        detector_arg=MARKER,
        rationale="тестовый пробник",
        owasp="LLM01:2025",
        effect="что-то произошло",
        next_check="что проверить у себя",
    )


class Scan(unittest.TestCase):
    def test_каждый_пробник_один_запрос(self):
        client = StubClient()
        probes = [_probe("t-001"), _probe("t-002")]
        results = scan(client, probes)
        self.assertEqual(client.calls, 2)
        self.assertEqual([r.probe_id for r in results], ["t-001", "t-002"])

    def test_срабатывание(self):
        results = scan(StubClient(f"Хорошо: {MARKER}"), [_probe()])
        self.assertEqual(results[0].verdict, VULNERABLE)

    def test_ошибка_запроса_не_вердикт(self):
        """Недоступная модель — это «нет данных», а не «устойчиво»."""
        results = scan(StubClient(fail=True), [_probe()])
        self.assertEqual(results[0].verdict, INCONCLUSIVE)
        self.assertIn("ошибка запроса", results[0].reason)

    def test_поля_пробника_доезжают_до_результата(self):
        results = scan(StubClient(), [_probe()])
        self.assertEqual(results[0].effect, "что-то произошло")
        self.assertEqual(results[0].next_check, "что проверить у себя")

    def test_колбэк_вызывается_по_ходу(self):
        seen = []
        scan(StubClient(), [_probe("t-001"), _probe("t-002")], on_result=seen.append)
        self.assertEqual(len(seen), 2)


class OwnSystemPrompt(unittest.TestCase):
    """Флаг --system-prompt: проверяем ограничение читателя, а не учебное."""

    def test_промпт_доезжает_до_модели(self):
        client = StubClient()
        scan(client, [_probe()], system_prompt="Ты ассистент банка. Код: MY_42.")
        self.assertEqual(client.systems, ["Ты ассистент банка. Код: MY_42."])

    def test_по_умолчанию_встроенный_промпт(self):
        client = StubClient()
        scan(client, [_probe()])
        self.assertIn("SEC_9F3A_KEY", client.systems[0])

    def test_свой_секрет_подставляется_в_пробники(self):
        adapted = with_secret(PROBES, "MY_42")
        args = {p.detector_arg for p in adapted if p.detector == "secret_leak"}
        self.assertEqual(args, {"MY_42"})
        self.assertEqual(len(adapted), len(PROBES))

    def test_без_секрета_пробники_на_утечку_убираются(self):
        """Показать «не сработали» там, где искать нечего, — обман."""
        adapted = with_secret(PROBES, None)
        self.assertFalse([p for p in adapted if p.detector == "secret_leak"])
        self.assertLess(len(adapted), len(PROBES))

    def test_источник_промпта_попадает_в_итог(self):
        results = scan(StubClient(), [_probe()])
        self.assertEqual(summarize(results, "m", "u")["prompt_source"], "встроенный учебный")
        own = summarize(results, "m", "u", "ваш: prompt.txt")["prompt_source"]
        self.assertEqual(own, "ваш: prompt.txt")


class Summarize(unittest.TestCase):
    def test_счётчики(self):
        results = scan(StubClient(f"вот {MARKER}"), [_probe("t-001"), _probe("t-002")])
        summary = summarize(results, "m", "http://127.0.0.1:1234")
        self.assertEqual((summary["total"], summary["vulnerable"], summary["safe"]), (2, 2, 0))

    def test_индекс_считается_по_весам(self):
        """critical 4, high 3: сработал только high → (7-3)/7 ≈ 57."""
        hit = scan(StubClient(f"вот {MARKER}"), [_probe("t-001", "high")])
        miss = scan(StubClient("Не могу."), [_probe("t-002", "critical")])
        summary = summarize(hit + miss, "m", "http://127.0.0.1:1234")
        self.assertEqual(summary["robustness_score"], 57)

    def test_ничего_не_сработало_индекс_сто(self):
        results = scan(StubClient("Не могу."), [_probe()])
        self.assertEqual(summarize(results, "m", "u")["robustness_score"], 100)
        self.assertEqual(results[0].verdict, SAFE)

    def test_разбивка_по_категориям_и_owasp(self):
        results = scan(StubClient(), [_probe()])
        summary = summarize(results, "m", "u")
        self.assertEqual(summary["by_category"]["prompt_injection"]["total"], 1)
        self.assertEqual(summary["by_owasp"]["LLM01:2025"]["total"], 1)

    def test_боевой_каталог_прогоняется_целиком(self):
        results = scan(StubClient(), PROBES)
        self.assertEqual(len(results), len(PROBES))


if __name__ == "__main__":
    unittest.main()
