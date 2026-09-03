"""Отчёт: его пересылают дальше, поэтому проверяем текст, а не факт вызова."""

import unittest

from amber.report import _plural, render_markdown
from amber.runner import scan, summarize
from tests.test_runner import MARKER, StubClient, _probe


def _summary(hits: int, misses: int, endpoint: str = "http://127.0.0.1:11434",
             prompt_source: str = "встроенный учебный") -> dict:
    results = []
    if hits:
        results += scan(StubClient(f"вот {MARKER}"),
                        [_probe(f"h-{i:03}") for i in range(hits)])
    if misses:
        results += scan(StubClient("Не могу."),
                        [_probe(f"m-{i:03}") for i in range(misses)])
    return summarize(results, "test-model", endpoint, prompt_source)


class Plural(unittest.TestCase):
    def test_согласование_числительных(self):
        cases = {1: "пробник", 2: "пробника", 4: "пробника", 5: "пробников",
                 11: "пробников", 12: "пробников", 21: "пробник", 22: "пробника"}
        for number, expected in cases.items():
            with self.subTest(number=number):
                self.assertEqual(_plural(number, "пробник", "пробника", "пробников"), expected)


class Markdown(unittest.TestCase):
    def test_шапка_и_счёт_сработавших(self):
        text = render_markdown(_summary(hits=1, misses=2))
        self.assertIn("# amber · test-model ·", text)
        self.assertIn("**Сработало: 1 из 3.**", text)

    def test_таблица_что_сработало(self):
        text = render_markdown(_summary(hits=1, misses=1))
        self.assertIn("## Что сработало", text)
        self.assertIn("| Пробник | Что произошло | OWASP |", text)
        self.assertIn("что-то произошло", text)

    def test_раздел_что_не_сработало_обязателен(self):
        """Без него отчёт читается как обвинительное заключение."""
        text = render_markdown(_summary(hits=1, misses=2))
        self.assertIn("## Что не сработало", text)
        self.assertIn("эти 2 пробника ограничения не пробили", text)

    def test_пустой_отчёт_не_объявляет_систему_устойчивой(self):
        text = render_markdown(_summary(hits=0, misses=3))
        self.assertIn("не сработали эти 3 пробника", text)
        self.assertNotIn("## Что не сработало\n\nНичего", text)

    def test_подробности_ведут_к_системе_читателя(self):
        text = render_markdown(_summary(hits=1, misses=0))
        self.assertIn("**Что проверить у себя:**", text)
        self.assertNotIn("рекомендаци", text.lower())

    def test_три_ручные_проверки_в_конце(self):
        text = render_markdown(_summary(hits=1, misses=1))
        self.assertIn("## Что сделать дальше руками", text)
        self.assertTrue(text.rstrip().endswith("Прочитайте, что утверждают ваши тесты."))

    def test_индекс_подан_как_несравнимая_с_безопасностью_величина(self):
        text = render_markdown(_summary(hits=1, misses=1))
        self.assertIn("это не оценка безопасности", text)


class PromptSource(unittest.TestCase):
    def test_источник_промпта_виден_в_отчёте(self):
        text = render_markdown(_summary(1, 1))
        self.assertIn("Системный промпт: встроенный учебный", text)

    def test_свой_промпт_получает_оговорку(self):
        text = render_markdown(_summary(1, 1, prompt_source="ваш: prompt.txt"))
        self.assertIn("Проверялся ваш системный промпт", text)

    def test_встроенный_промпт_без_оговорки(self):
        self.assertNotIn("Проверялся ваш", render_markdown(_summary(1, 1)))


class CloudNote(unittest.TestCase):
    def test_внешний_эндпоинт_получает_оговорку(self):
        text = render_markdown(_summary(1, 1, endpoint="https://api.deepseek.com"))
        self.assertIn("Прогон против внешнего API", text)

    def test_локальный_эндпоинт_без_оговорки(self):
        text = render_markdown(_summary(1, 1, endpoint="http://127.0.0.1:11434"))
        self.assertNotIn("Прогон против внешнего API", text)


if __name__ == "__main__":
    unittest.main()
