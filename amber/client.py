"""Клиент к OpenAI-совместимому эндпоинту. Без внешних зависимостей."""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def env_api_key() -> str:
    """Ключ из окружения. В аргументе командной строки он виден в `ps`."""
    for name in ("AMBER_API_KEY", "OPENAI_API_KEY"):
        value = os.environ.get(name)
        if value:
            return value
    return "dummy"


def ssl_context() -> ssl.SSLContext:
    """Корни для TLS.

    У сборки python.org на macOS системный стор пуст, и любой https падает
    с CERTIFICATE_VERIFY_FAILED. Если рядом лежит certifi — берём корни
    оттуда; требовать его установку не станем.
    """
    context = ssl.create_default_context()
    if not context.get_ca_certs():
        try:
            import certifi

            context.load_verify_locations(certifi.where())
        except Exception:
            pass
    return context


def is_local(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in LOCAL_HOSTS or host.startswith("192.168.") or host.endswith(".local")


class LLMError(RuntimeError):
    """Запрос к модели не удался."""


@dataclass
class Reply:
    text: str
    latency_s: float
    finish_reason: str | None


class LLMClient:
    """Минимальный чат-клиент к /v1/chat/completions."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout: int = 120,
        retries: int = 2,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key or env_api_key()
        self._ssl = ssl_context()
        self.timeout = timeout
        self.retries = retries

    def chat(self, system: str | None, user: str, temperature: float = 0.0) -> Reply:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": user})

        payload = json.dumps(
            {"model": self.model, "messages": messages, "temperature": temperature},
            ensure_ascii=False,
        ).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        last_error: Exception | str | None = None
        for attempt in range(self.retries + 1):
            started = time.monotonic()
            try:
                with urllib.request.urlopen(
                    request, timeout=self.timeout, context=self._ssl
                ) as response:
                    body = json.loads(response.read().decode("utf-8"))
                choice = body["choices"][0]
                return Reply(
                    text=choice["message"].get("content") or "",
                    latency_s=round(time.monotonic() - started, 2),
                    finish_reason=choice.get("finish_reason"),
                )
            except urllib.error.HTTPError as exc:
                last_error = _http_detail(exc)
                if exc.code == 429 and attempt < self.retries:
                    # Провайдер сам говорит, сколько ждать, — слушаем его.
                    time.sleep(_retry_after(exc, attempt))
                    continue
                if exc.code in (400, 401, 403, 404):
                    break  # ретраить бессмысленно: ключ, модель или адрес
                if attempt < self.retries:
                    time.sleep(1.5 * (attempt + 1))
            except (urllib.error.URLError, OSError, KeyError, IndexError, ValueError) as exc:
                last_error = _tls_hint(exc)
                if attempt < self.retries:
                    time.sleep(1.5 * (attempt + 1))

        raise LLMError(f"{self.base_url}: {last_error}")

    def check(self) -> str | None:
        """Причина недоступности эндпоинта или None, если всё в порядке.

        «Не отвечает» — плохой ответ: чаще всего дело в ключе или в TLS,
        и человек должен узнать об этом сразу, а не гадать.
        """
        request = urllib.request.Request(
            f"{self.base_url}/v1/models",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10, context=self._ssl):
                return None
        except urllib.error.HTTPError as exc:
            return _http_detail(exc)
        except OSError as exc:
            return str(_tls_hint(exc))

    def ping(self) -> bool:
        return self.check() is None


def _retry_after(exc: urllib.error.HTTPError, attempt: int) -> float:
    """Пауза перед повтором: сколько просил провайдер, иначе растущая."""
    header = exc.headers.get("Retry-After") if exc.headers else None
    try:
        return min(float(header), 60.0)
    except (TypeError, ValueError):
        return 2.0 * (attempt + 1)


def _http_detail(exc: urllib.error.HTTPError) -> str:
    """Понятная причина вместо голого кода: лимит, ключ, адрес."""
    known = {
        401: "ключ не принят (401)",
        403: "доступ запрещён (403)",
        404: "адрес или модель не найдены (404)",
        429: "лимит провайдера (429)",
    }
    reason = known.get(exc.code, f"HTTP {exc.code}")
    try:
        body = json.loads(exc.read().decode("utf-8"))
        message = body.get("error", {}).get("message") or body.get("message")
    except Exception:
        message = None
    return f"{reason}: {message}" if message else reason


def _tls_hint(exc: Exception) -> Exception | str:
    """Отдельное сообщение для отсутствующих корневых сертификатов."""
    if "CERTIFICATE_VERIFY_FAILED" in str(exc):
        return ("нет корневых сертификатов для TLS — на macOS запустите "
                "«Install Certificates.command» из папки установленного Python "
                "или поставьте certifi")
    return exc
