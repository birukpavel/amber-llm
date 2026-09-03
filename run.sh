#!/bin/bash
# Запуск и остановка сканера. Процессы отвязаны от терминала — переживают его закрытие.
cd "$(dirname "$0")"
LOG=~/.cache/amber
mkdir -p "$LOG"

start() {
  pgrep -f "amber.mock" >/dev/null || {
    nohup python3 -m amber.mock > "$LOG/mock.log" 2>&1 &
    echo "учебный стенд  → http://127.0.0.1:9911"
  }
  pgrep -f "amber.server" >/dev/null || {
    nohup python3 -m amber.server --no-open > "$LOG/web.log" 2>&1 &
    echo "интерфейс      → http://127.0.0.1:8080"
  }
  sleep 2
  curl -s -m 3 http://127.0.0.1:8080/api/catalog >/dev/null \
    && echo "готово" || echo "интерфейс не отвечает, смотри $LOG/web.log"
}

stop() {
  pkill -f "amber.server" 2>/dev/null && echo "интерфейс остановлен"
  pkill -f "amber.mock" 2>/dev/null && echo "стенд остановлен"
  true
}

status() {
  pgrep -f "amber.server" >/dev/null && echo "интерфейс: работает (:8080)" || echo "интерфейс: остановлен"
  pgrep -f "amber.mock"   >/dev/null && echo "стенд:     работает (:9911)" || echo "стенд:     остановлен"
  curl -s -m 3 http://localhost:1234/v1/models >/dev/null 2>&1 \
    && echo "LM Studio: отвечает (:1234)" || echo "LM Studio: не отвечает"
}

case "${1:-start}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 1; start ;;
  status)  status ;;
  *) echo "использование: ./run.sh [start|stop|restart|status]"; exit 1 ;;
esac
