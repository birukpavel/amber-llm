"""Целостность каталога: страховка для тринадцатого пробника, который допишут потом."""

import unittest

from amber.detectors import DETECTORS
from amber.probes import CATEGORY_TITLES, MARKER, OWASP_TITLES, PROBES, SECRET, SYSTEM_PROMPT


class Catalog(unittest.TestCase):
    def test_идентификаторы_уникальны(self):
        ids = [p.id for p in PROBES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_детектор_существует(self):
        for probe in PROBES:
            with self.subTest(probe=probe.id):
                self.assertIn(probe.detector, DETECTORS)

    def test_аргумент_детектора_на_месте(self):
        """Всем детекторам, кроме fingerprint, нужно искомое значение."""
        for probe in PROBES:
            with self.subTest(probe=probe.id):
                if probe.detector == "fingerprint":
                    self.assertIsNone(probe.detector_arg)
                else:
                    self.assertTrue(probe.detector_arg)

    def test_категория_и_owasp_имеют_название(self):
        for probe in PROBES:
            with self.subTest(probe=probe.id):
                self.assertIn(probe.category, CATEGORY_TITLES)
                self.assertIn(probe.owasp, OWASP_TITLES)

    def test_критичность_из_известных(self):
        for probe in PROBES:
            with self.subTest(probe=probe.id):
                self.assertIn(probe.severity, ("critical", "high", "medium", "low"))

    def test_тексты_заполнены(self):
        for probe in PROBES:
            with self.subTest(probe=probe.id):
                self.assertTrue(probe.prompt.strip())
                self.assertTrue(probe.rationale.strip())
                self.assertGreater(len(probe.effect), 10, "«что произошло» — не заглушка")
                self.assertGreater(len(probe.next_check), 40, "«что проверить» — не заглушка")


class SystemPrompt(unittest.TestCase):
    def test_обе_контролируемые_величины_в_промпте(self):
        self.assertIn(SECRET, SYSTEM_PROMPT)
        self.assertIn(MARKER, SYSTEM_PROMPT)

    def test_пробники_не_содержат_секрета(self):
        """Секрет модель должна выдать сама, а не получить его в запросе."""
        for probe in PROBES:
            with self.subTest(probe=probe.id):
                self.assertNotIn(SECRET, probe.prompt)


if __name__ == "__main__":
    unittest.main()
