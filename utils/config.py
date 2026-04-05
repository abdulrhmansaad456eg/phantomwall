import json
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict, field


@dataclass
class WAFConfig:
    enabled: bool = True
    blocking_mode: bool = True
    sensitivity: str = "medium"
    rate_limit: int = 100
    language: str = "en"
    port: int = 8080
    host: str = "127.0.0.1"
    whitelist: list = field(default_factory=list)
    blacklist: list = field(default_factory=list)
    log_retention_days: int = 30
    enable_logging: bool = True
    max_payload_size: int = 1048576
    custom_rules: list = field(default_factory=list)
    alert_email: str = ""
    enable_notifications: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WAFConfig":
        return cls(**data)


class ConfigManager:
    def __init__(self, config_path: str = "phantomwall.json"):
        self.config_path = config_path
        self.config = WAFConfig()
        self._load()
    
    def _load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.config = WAFConfig.from_dict(data)
            except (json.JSONDecodeError, TypeError, ValueError):
                self.config = WAFConfig()
                self._save()
        else:
            self._save()
    
    def _save(self):
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config.to_dict(), f, indent=2, ensure_ascii=False)
    
    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any):
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            self._save()
    
    def update(self, updates: Dict[str, Any]):
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        self._save()
    
    def get_all(self) -> Dict[str, Any]:
        return self.config.to_dict()
    
    def reset_to_defaults(self):
        self.config = WAFConfig()
        self._save()
    
    def add_to_whitelist(self, ip: str):
        if ip not in self.config.whitelist:
            self.config.whitelist.append(ip)
            self._save()
    
    def remove_from_whitelist(self, ip: str):
        if ip in self.config.whitelist:
            self.config.whitelist.remove(ip)
            self._save()
    
    def add_to_blacklist(self, ip: str):
        if ip not in self.config.blacklist:
            self.config.blacklist.append(ip)
            self._save()
    
    def remove_from_blacklist(self, ip: str):
        if ip in self.config.blacklist:
            self.config.blacklist.remove(ip)
            self._save()
    
    def add_custom_rule(self, name: str, pattern: str, attack_type: str, threat_level: str):
        rule = {
            "name": name,
            "pattern": pattern,
            "attack_type": attack_type,
            "threat_level": threat_level
        }
        self.config.custom_rules.append(rule)
        self._save()
    
    def remove_custom_rule(self, index: int):
        if 0 <= index < len(self.config.custom_rules):
            self.config.custom_rules.pop(index)
            self._save()

