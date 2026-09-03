"""Клиент: ключи, локальность эндпоинта и внятность ошибок.

Все три пункта — из реальных проколов: ключ светился в `ps`, неверный ключ
выглядел как «эндпоинт не отвечает», а отсутствие TLS-корней — тоже.
"""

import unittest
import urllib.error
from unittest import mock

from amber.client import _http_detail, _retry_after, _tls_hint, env_api_key, is_local


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = {"Retry-After": retry_after} if retry_after else {}
    return urllib.error.HTTPError("https://api.example.com", code, "", headers, None)


class LocalOrCloud(unittest.TestCase):
    def test_локальные_адреса(self):
        for url in ("http://localhost:1234", "http://127.0.0.1:11434",
                    "http://192.168.1.50:8000", "http://gpu-box.local:1234"):
            with self.subTest(url=url):
                self.assertTrue(is_local(url))

    def test_внешние_адреса(self):
        for url in ("https://api.deepseek.com", "https://api.openai.com"):
            with self.subTest(url=url):
                self.assertFalse(is_local(url))


class ApiKeyFromEnv(unittest.TestCase):
    def test_приоритет_переменных(self):
        with mock.patch.dict("os.environ", {"AMBER_API_KEY": "a", "OPENAI_API_KEY": "b"}, clear=True):
            self.assertEqual(env_api_key(), "a")
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "b"}, clear=True):
            self.assertEqual(env_api_key(), "b")

    def test_без_переменных_заглушка(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(env_api_key(), "dummy")


class ErrorsExplainThemselves(unittest.TestCase):
    def test_коды_переводятся_в_причину(self):
        self.assertIn("ключ не принят", _http_detail(_http_error(401)))
        self.assertIn("лимит провайдера", _http_detail(_http_error(429)))
        self.assertIn("не найдены", _http_detail(_http_error(404)))
        self.assertIn("500", _http_detail(_http_error(500)))

    def test_пауза_из_заголовка(self):
        self.assertEqual(_retry_after(_http_error(429, "3"), 0), 3.0)

    def test_пауза_ограничена_минутой(self):
        self.assertEqual(_retry_after(_http_error(429, "999"), 0), 60.0)

    def test_без_заголовка_растущая_пауза(self):
        self.assertEqual(_retry_after(_http_error(429), 0), 2.0)
        self.assertEqual(_retry_after(_http_error(429), 1), 4.0)

    def test_подсказка_про_сертификаты(self):
        hint = _tls_hint(OSError("[SSL: CERTIFICATE_VERIFY_FAILED] unable to get issuer"))
        self.assertIn("корневых сертификатов", str(hint))

    def test_прочие_ошибки_не_трогаем(self):
        original = OSError("Connection refused")
        self.assertIs(_tls_hint(original), original)


if __name__ == "__main__":
    unittest.main()
