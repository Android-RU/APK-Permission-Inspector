# 🧩 APK-Permission-Inspector

**APK-Permission-Inspector** — это утилита на Python для анализа разрешений (`permissions`) Android-приложений. Скрипт извлекает и классифицирует разрешения из **APK-файла** или **AndroidManifest.xml**, показывает детальную информацию, предупреждает о потенциально опасных разрешениях и может сравнивать две версии приложения.

> ⚡️ Основная цель — помочь разработчикам, QA и специалистам по безопасности быстро увидеть, какие разрешения запрашивает приложение и как они изменяются между релизами.

---

## 🚀 Возможности

- 📦 Извлечение и парсинг `AndroidManifest.xml` из APK  
- 🧾 Список всех разрешений с классификацией:
  - `normal`
  - `dangerous`
  - `signature`
  - `unknown`
- 🕵️‍♂️ Подсветка чувствительных разрешений (`dangerous` и `signature`)
- ⚙️ Фильтрация по типу (`--only dangerous`, `--only signature`)
- 🔍 Сравнение двух версий APK/манифеста (появившиеся и удалённые разрешения)
- 💾 Экспорт отчёта в JSON
- 🎨 Цветной CLI-вывод с таблицами (на базе библиотеки [Rich](https://github.com/Textualize/rich))
- 🧱 Код возврата для CI/CD:
  - `0` — успешный анализ  
  - `1` — ошибка входных данных  
  - `3` — появились новые опасные разрешения (`--fail-on-new-dangerous`)

---

## 🧰 Установка

### Требования:
- **Python 3.9+**
- ОС: Windows / macOS / Linux

### Установка зависимостей:
```bash
pip install typer rich apkutils2 lxml
````

### Клонирование репозитория:

```bash
git clone https://github.com/Android-RU/APK-Permission-Inspector.git
cd APK-Permission-Inspector
```

---

## 🧠 Использование

### 1. Анализ APK

```bash
python permission.py analyze --apk app-release.apk
```

### 2. Анализ AndroidManifest.xml

```bash
python permission.py analyze --manifest AndroidManifest.xml
```

### 3. Фильтр только опасных разрешений

```bash
python permission.py analyze --apk app.apk --only dangerous
```

### 4. Сравнение двух версий APK

```bash
python permission.py analyze --apk old.apk --compare-apk new.apk
```

### 5. Проверка на новые опасные разрешения (для CI)

```bash
python permission.py analyze --apk old.apk --compare-apk new.apk --fail-on-new-dangerous
```

### 6. Экспорт отчёта в JSON

```bash
python permission.py analyze --apk app.apk -o report.json
```

---

## 📊 Пример вывода

```
╔══════════════════════════════════════════════════════════════╗
║                    Permissions (Base)                        ║
╚══════════════════════════════════════════════════════════════╝
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Permission                                     ┃ Category   ┃ Group      ┃ Sensitive  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ android.permission.INTERNET                    │ normal     │ NETWORK    │ ❌         │
│ android.permission.ACCESS_FINE_LOCATION        │ dangerous  │ LOCATION   │ ✅         │
│ android.permission.RECORD_AUDIO                │ dangerous  │ MICROPHONE │ ✅         │
│ android.permission.CAMERA                      │ dangerous  │ CAMERA     │ ✅         │
└────────────────────────────────────────────────┴────────────┴────────────┴────────────┘
```

---

## ⚖️ Коды возврата

| Код | Значение                                                     |
| --- | ------------------------------------------------------------ |
| `0` | Успешный анализ                                              |
| `1` | Ошибка ввода или парсинга                                    |
| `3` | Найдены новые опасные разрешения (`--fail-on-new-dangerous`) |

---

## ⚙️ Аргументы CLI

| Аргумент                  | Описание                                                         |
| ------------------------- | ---------------------------------------------------------------- |
| `--apk` / `-a`            | Путь к APK-файлу                                                 |
| `--manifest` / `-m`       | Путь к AndroidManifest.xml                                       |
| `--compare-apk`           | Второй APK для сравнения                                         |
| `--compare-manifest`      | Второй манифест для сравнения                                    |
| `--only`                  | Фильтрация по категориям (normal, dangerous, signature, unknown) |
| `--fail-on-new-dangerous` | Возврат кода 3 при появлении новых dangerous                     |
| `--output` / `-o`         | Сохранение отчёта в JSON                                         |
| `--no-color`              | Отключить цветной вывод                                          |

---

## 📂 Пример JSON-отчёта

```json
{
  "permissions": [
    {
      "name": "android.permission.ACCESS_FINE_LOCATION",
      "category": "dangerous",
      "group": "LOCATION",
      "sensitive": true
    },
    {
      "name": "android.permission.INTERNET",
      "category": "normal",
      "group": "NETWORK",
      "sensitive": false
    }
  ],
  "diff": {
    "added": ["android.permission.ACCESS_MEDIA_LOCATION"],
    "removed": [],
    "newDangerous": ["android.permission.ACCESS_MEDIA_LOCATION"]
  }
}
```

---

## 🧩 Применение

**Для разработчиков:**
→ Проверка, какие разрешения реально запрашивает ваше приложение.

**Для QA и безопасности:**
→ Быстрое выявление новых опасных разрешений между версиями.

**Для CI/CD:**
→ Добавьте шаг проверки в пайплайн и предотвращайте релизы с избыточными разрешениями.

---

## 🧱 Пример интеграции в GitHub Actions

```yaml
- name: Check Android permissions
  run: |
    python permission.py analyze --apk old.apk --compare-apk new.apk --fail-on-new-dangerous
```

---

## 📜 Лицензия

Проект распространяется по лицензии **MIT**.
Вы можете свободно использовать, изменять и распространять данный инструмент с сохранением указания автора.

---

> 🧠 *APK-Permission-Inspector — лёгкий инструмент, который даёт прозрачность вашим Android-приложениям.*
