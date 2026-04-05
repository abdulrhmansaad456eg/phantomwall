import json
import os
from typing import Dict, Optional


class I18n:
    def __init__(self, locale: str = "en"):
        self.locale = locale
        self.translations: Dict[str, str] = {}
        self.locales_dir = os.path.join(os.path.dirname(__file__), "..", "locales")
        self.available_locales = ["en", "ko", "ar"]
        self._load_translations()
    
    def _load_translations(self):
        locale_file = os.path.join(self.locales_dir, f"{self.locale}.json")
        default_file = os.path.join(self.locales_dir, "en.json")
        
        try:
            with open(locale_file, "r", encoding="utf-8") as f:
                self.translations = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            with open(default_file, "r", encoding="utf-8") as f:
                self.translations = json.load(f)
    
    def set_locale(self, locale: str) -> bool:
        if locale in self.available_locales:
            self.locale = locale
            self._load_translations()
            return True
        return False
    
    def get(self, key: str, default: Optional[str] = None) -> str:
        return self.translations.get(key, default or key)
    
    def get_available_locales(self) -> list:
        return self.available_locales
    
    def get_locale_name(self, locale: str) -> str:
        names = {
            "en": "English",
            "ko": "한국어 (Korean)",
            "ar": "العربية (Arabic)"
        }
        return names.get(locale, locale)


def get_text_direction(locale: str) -> str:
    return "rtl" if locale == "ar" else "ltr"


def format_datetime(dt, locale: str = "en") -> str:
    formats = {
        "en": "%Y-%m-%d %H:%M:%S",
        "ko": "%Y년 %m월 %d일 %H:%M:%S",
        "ar": "%Y/%m/%d %H:%M:%S"
    }
    return dt.strftime(formats.get(locale, formats["en"]))
