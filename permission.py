#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
permission.py — анализатор разрешений Android (APK/AndroidManifest.xml)

Функциональность:
 - Извлекает список разрешений из APK или AndroidManifest.xml
 - Классифицирует их (normal/dangerous/signature/unknown)
 - Сравнивает две версии (diff)
 - Поддерживает фильтры и экспорт JSON
 - Использует цветной CLI (rich) и удобный интерфейс (typer)
"""

import json
import sys
import zipfile
from pathlib import Path
from typing import List, Optional, Dict, Any

import typer
from rich.console import Console
from rich.table import Table
from lxml import etree

try:
    import apkutils2
except ImportError:
    apkutils2 = None

app = typer.Typer(help="Android Permission Inspector — анализатор разрешений из APK/Manifest")
console = Console()

# ---------------------------------------------------------
# Встроенный словарь известных разрешений (сокращённый)
# ---------------------------------------------------------
PERMISSION_CATEGORIES = {
    "android.permission.INTERNET": ("normal", "NETWORK"),
    "android.permission.ACCESS_NETWORK_STATE": ("normal", "NETWORK"),
    "android.permission.ACCESS_FINE_LOCATION": ("dangerous", "LOCATION"),
    "android.permission.ACCESS_COARSE_LOCATION": ("dangerous", "LOCATION"),
    "android.permission.READ_CONTACTS": ("dangerous", "CONTACTS"),
    "android.permission.WRITE_CONTACTS": ("dangerous", "CONTACTS"),
    "android.permission.RECORD_AUDIO": ("dangerous", "MICROPHONE"),
    "android.permission.CAMERA": ("dangerous", "CAMERA"),
    "android.permission.READ_SMS": ("dangerous", "SMS"),
    "android.permission.SEND_SMS": ("dangerous", "SMS"),
    "android.permission.RECEIVE_SMS": ("dangerous", "SMS"),
    "android.permission.READ_EXTERNAL_STORAGE": ("dangerous", "STORAGE"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("dangerous", "STORAGE"),
    "android.permission.POST_NOTIFICATIONS": ("dangerous", "NOTIFICATIONS"),
    "android.permission.INSTALL_PACKAGES": ("signature", "SYSTEM"),
    "android.permission.READ_LOGS": ("signature", "SYSTEM"),
}

# ---------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------
def load_manifest_from_apk(apk_path: Path) -> Optional[bytes]:
    """Извлекает AndroidManifest.xml из APK"""
    if not apk_path.exists():
        console.print(f"[red]Ошибка: APK-файл {apk_path} не найден[/red]")
        return None
    try:
        with zipfile.ZipFile(apk_path, "r") as zip_ref:
            data = zip_ref.read("AndroidManifest.xml")
            return data
    except Exception as e:
        console.print(f"[red]Ошибка извлечения AndroidManifest.xml: {e}[/red]")
        return None


def parse_manifest(data: bytes) -> Optional[etree._ElementTree]:
    """Парсит XML (возможен бинарный формат AXML через apkutils2)"""
    try:
        # Если есть apkutils2, используем его для декодирования бинарного AXML
        if apkutils2:
            return etree.fromstring(apkutils2.APK.load_manifest_xml(data))
        # Иначе — пробуем напрямую
        return etree.fromstring(data)
    except Exception as e:
        console.print(f"[red]Ошибка парсинга манифеста: {e}[/red]")
        return None


def extract_permissions(manifest_root: etree._ElementTree) -> List[str]:
    """Извлекает uses-permission / uses-permission-sdk-23"""
    perms = []
    if manifest_root is None:
        return perms
    ns = {"android": "http://schemas.android.com/apk/res/android"}
    for tag in ["uses-permission", "uses-permission-sdk-23"]:
        for el in manifest_root.findall(tag):
            name = el.get("{http://schemas.android.com/apk/res/android}name")
            if name:
                perms.append(name.strip())
    # Уникализируем
    return sorted(set(perms))


def classify_permission(name: str) -> Dict[str, Any]:
    """Классифицирует разрешение по словарю"""
    if name in PERMISSION_CATEGORIES:
        cat, group = PERMISSION_CATEGORIES[name]
    else:
        cat, group = ("unknown", None)
    sensitive = cat in ("dangerous", "signature")
    return {"name": name, "category": cat, "group": group, "sensitive": sensitive}


def print_table(permissions: List[Dict[str, Any]], title: str = "Permissions"):
    """Вывод таблицы разрешений в консоль"""
    table = Table(title=title)
    table.add_column("Permission", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Group", style="green")
    table.add_column("Sensitive", style="yellow")

    for p in permissions:
        color = {
            "dangerous": "red",
            "signature": "yellow",
            "unknown": "dim",
            "normal": "white"
        }.get(p["category"], "white")
        table.add_row(
            f"[{color}]{p['name']}[/{color}]",
            p["category"],
            p["group"] or "",
            "✅" if p["sensitive"] else "❌"
        )

    console.print(table)


def diff_permissions(old: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Сравнивает два списка разрешений"""
    old_names = {p["name"]: p for p in old}
    new_names = {p["name"]: p for p in new}
    added = [n for n in new_names if n not in old_names]
    removed = [n for n in old_names if n not in new_names]
    new_dangerous = [n for n in added if new_names[n]["category"] == "dangerous"]
    return {"added": added, "removed": removed, "newDangerous": new_dangerous}


def export_json(data: Dict[str, Any], path: Path):
    """Сохраняет отчёт в JSON"""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        console.print(f"[green]JSON-отчёт сохранён: {path}[/green]")
    except Exception as e:
        console.print(f"[red]Ошибка записи JSON: {e}[/red]")


# ---------------------------------------------------------
# Основная логика CLI
# ---------------------------------------------------------
@app.command()
def analyze(
    apk: Optional[Path] = typer.Option(None, "--apk", "-a", help="Путь к APK"),
    manifest: Optional[Path] = typer.Option(None, "--manifest", "-m", help="Путь к AndroidManifest.xml"),
    compare_apk: Optional[Path] = typer.Option(None, "--compare-apk", help="Второй APK для сравнения"),
    compare_manifest: Optional[Path] = typer.Option(None, "--compare-manifest", help="Второй манифест для сравнения"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Путь для JSON-отчёта"),
    only: Optional[List[str]] = typer.Option(None, "--only", help="Фильтр по категориям: normal, dangerous, signature, unknown"),
    fail_on_new_dangerous: bool = typer.Option(False, "--fail-on-new-dangerous", help="Завершить с кодом 3, если появились новые dangerous"),
    no_color: bool = typer.Option(False, "--no-color", help="Отключить цвета")
):
    """Основная команда анализа"""
    if no_color:
        console.no_color = True

    # Загрузка первого манифеста
    data1 = None
    if apk:
        data1 = load_manifest_from_apk(apk)
    elif manifest:
        data1 = Path(manifest).read_bytes()
    else:
        console.print("[red]Ошибка: укажите --apk или --manifest[/red]")
        raise typer.Exit(code=1)

    manifest1 = parse_manifest(data1)
    if manifest1 is None:
        raise typer.Exit(code=1)

    perms1 = [classify_permission(p) for p in extract_permissions(manifest1)]
    if only:
        perms1 = [p for p in perms1 if p["category"] in only]

    print_table(perms1, "Permissions (Base)")

    report = {
        "permissions": perms1,
        "diff": None,
    }

    # Сравнение двух APK/манифестов
    if compare_apk or compare_manifest:
        data2 = None
        if compare_apk:
            data2 = load_manifest_from_apk(compare_apk)
        elif compare_manifest:
            data2 = Path(compare_manifest).read_bytes()
        manifest2 = parse_manifest(data2)
        perms2 = [classify_permission(p) for p in extract_permissions(manifest2)]
        d = diff_permissions(perms1, perms2)
        report["diff"] = d

        # Выводим результаты сравнения
        if d["added"] or d["removed"]:
            console.print("\n[bold cyan]Сравнение версий:[/bold cyan]")
            if d["added"]:
                console.print(f"[green]+ Добавлены:[/green] {', '.join(d['added'])}")
            if d["removed"]:
                console.print(f"[red]- Удалены:[/red] {', '.join(d['removed'])}")
            if d["newDangerous"]:
                console.print(f"[red bold]! Новые опасные:[/red bold] {', '.join(d['newDangerous'])}")

        if fail_on_new_dangerous and d["newDangerous"]:
            console.print("[red]Найдены новые dangerous разрешения![/red]")
            if output:
                export_json(report, output)
            raise typer.Exit(code=3)

    # Экспорт JSON
    if output:
        export_json(report, output)

    raise typer.Exit(code=0)


# ---------------------------------------------------------
# Точка входа
# ---------------------------------------------------------
if __name__ == "__main__":
    app()