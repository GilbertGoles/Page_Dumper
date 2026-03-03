# Page_Dumper

# Page Dumper

CLI-утилита + Web GUI для сбора и анализа исходников веб-страниц (recon / bug bounty).

Работает с доменами и IP:port. Даёшь URL — получаешь структурированный дамп + отчёт.

## Установка

```bash
pip install -r requirements.txt
chmod +x dumper.py web.py
```

## CLI

```bash
# Базовый
./dumper.py https://example.com

# IP с портом + виртуальный хост
./dumper.py http://10.0.0.1:8080 --host-header target.local -k

# Полный рекон
./dumper.py https://target.com -o -d 3 -b -t 20 --json-report --html-report --wayback

# Stealth (тихий сбор без банов)
./dumper.py https://target.com --stealth          # medium (default)
./dumper.py https://target.com --stealth 1         # light
./dumper.py https://target.com --stealth 3         # heavy (QRATOR, агрессивный WAF)

# С логированием
./dumper.py https://target.com -b --log scan.log

# Через конфиг-файл
./dumper.py --config scan.json

# С авторизацией
./dumper.py https://target.com --cookie "s=abc" -H "Authorization: Bearer token"

# Через Burp
./dumper.py https://target.com --proxy http://127.0.0.1:8080 -k
```

## Web GUI

```bash
python3 web.py
# Открыть http://127.0.0.1:5000
```

Тёмный интерфейс с формой для всех параметров. Live-вывод через SSE (Server-Sent Events), кнопка Stop Scan для graceful shutdown, отображение report.txt и report.json.

## Config File

Вместо CLI-флагов можно использовать JSON-конфиг (`config.example.json`):

```json
{
  "url": "https://target.com",
  "depth": 2,
  "bruteforce": true,
  "threads": 20,
  "json_report": true,
  "cookies": "session=abc",
  "headers": {"Authorization": "Bearer xxx"},
  "proxy": "http://127.0.0.1:8080",
  "insecure": true
}
```

CLI-аргументы перекрывают значения из конфига.

## Структура вывода

```
target_com_250225_143022/
├── 00_main.html
├── 01_js/
│   ├── inline/
│   ├── sourcemaps/
│   └── sourcemaps_extracted/
├── 02_css/
├── 03_external/{js,css}/
├── 04_extra/
├── 05_api_responses/
├── 06_bruteforce/
├── 07_wayback/              # --wayback
├── 08_git/                  # авто при обнаружении .git
├── report.txt
├── report.json              # --json-report
└── report.html              # --html-report (donut chart, таблицы, секреты)
```

## Флаги

| Флаг | Описание |
|---|---|
| `-o` | Один `full_dump.txt` вместо дерева |
| `-d N` | Глубина рекурсии JS (default: 1) |
| `-b` | Bruteforce директорий (~90 путей) |
| `-t N` | Потоки bruteforce (default: 10) |
| `-c FILE` | JSON конфиг-файл |
| `--host-header` | Override Host (IP + виртуальный хост) |
| `--json-report` | Сохранить report.json |
| `--html-report` | HTML отчёт с графиками и таблицами |
| `-H` | Кастомный заголовок (повторяемый) |
| `--cookie` | Куки |
| `--proxy` | HTTP-прокси |
| `-k` | Отключить SSL |
| `-A` | User-Agent |
| `--no-extras` | Пропустить robots.txt и т.д. |
| `--timeout N` | Таймаут запросов (default: 15) |
| `--stealth [N]` | Тихий режим: 1=light 2=medium 3=heavy (default: 2) |
| `--delay N` | Задержка между запросами (сек), обход WAF |
| `--wayback` | Загрузить старые JS из Wayback Machine |
| `--log FILE` | Дублировать лог в файл |

## Что анализируется

- **JS/CSS** — внешние, inline, source maps, CSS `url()` пути
- **Source maps** — `sourcesContent` (исходники), `names` (переменные), `sources` (структура)
- **Секреты** — API-ключи, JWT, AWS, GitHub/Slack, пароли, IP, email
- **Конфиги** — `window.__CONFIG__`, `__NEXT_DATA__`, `__INITIAL_STATE__`
- **API probing** — авто-запрос найденных эндпоинтов + CORS check + рекурсивный JSON парсинг
- **DOM Sinks** — eval, innerHTML, document.write, postMessage, dangerouslySetInnerHTML
- **Субдомены** — пассивный поиск `*.target.com` (отключается для IP)
- **Bruteforce** — admin, .git, .env, backup, phpinfo, swagger, wp-* + redirect tracking
- **Git dump** — автоматическое извлечение HEAD, config, logs при обнаружении `.git`
- **Wayback Machine** — CDX API + скачивание старых JS для поиска удалённых уязвимостей
- **Security headers** — CSP, HSTS, X-Frame-Options
- **Технологии** — React, Angular, Vue, Next.js, WordPress, Webpack
- **HTML-комментарии**, robots.txt, sitemap.xml, security.txt
- **Stealth mode** — `--stealth [1-3]`: ротация User-Agent (20 шт), ротация Accept-Language, Sec-Ch-Ua/Sec-Fetch подстраиваются под UA (Firefox без Chrome-заголовков). Level 1: 5t/1s/10UA, Level 2: 3t/1-3s/16UA, Level 3: 1t/3-5s/20UA. В Web GUI — dropdown + "Run Bruteforce" после stealth-скана
- **WAF detection** — автоматическая проверка перед bruteforce (SQLi/XSS payload), определение Cloudflare, AWS, Akamai и др.
- **Rate limiting** — `--delay` для задержки между запросами, глобальный лимит для всех потоков
- **Graceful shutdown** — Ctrl+C / Stop Scan сохраняет всё, что уже собрано
- **Инкрементальная запись** — файлы пишутся на диск сразу после скачивания
- **Логирование** — `--log` для дублирования вывода в файл

## IP:port

```bash
./dumper.py http://62.173.140.174:16108 -b -k
./dumper.py http://10.0.0.1:8080 --host-header intranet.corp -k
```

При IP-таргете поиск субдоменов автоматически отключается. `--host-header` позволяет указать виртуальный хост.

## Лимиты

- Файлы > 5 MB — сохраняются, но не парсятся regex-ами
- Файлы > 20 MB — пропускаются
- API probing — макс. 50 эндпоинтов
- Retry: 2 попытки с backoff для 429/5xx
