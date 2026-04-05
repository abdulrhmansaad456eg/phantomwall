import re
import time
import hashlib
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    CSRF = "csrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    FILE_INCLUSION = "file_inclusion"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    BRUTE_FORCE = "brute_force"
    RATE_LIMIT = "rate_limit_exceeded"
    UNKNOWN = "unknown"


@dataclass
class SecurityEvent:
    timestamp: str
    attack_type: str
    threat_level: str
    source_ip: str
    method: str
    path: str
    payload: str
    action: str
    rule_id: str
    request_id: str
    headers: Dict[str, str]
    user_agent: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "attack_type": self.attack_type,
            "threat_level": self.threat_level,
            "source_ip": self.source_ip,
            "method": self.method,
            "path": self.path,
            "payload": self.payload[:500] if len(self.payload) > 500 else self.payload,
            "action": self.action,
            "rule_id": self.rule_id,
            "request_id": self.request_id,
            "headers": dict(self.headers),
            "user_agent": self.user_agent
        }


@dataclass
class WAFResponse:
    allowed: bool
    event: Optional[SecurityEvent]
    status_code: int
    message: str
    request_id: str


class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, float] = {}
        self.block_duration = 300
    
    def is_blocked(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            if time.time() - self.blocked_ips[ip] < self.block_duration:
                return True
            del self.blocked_ips[ip]
        return False
    
    def check_rate(self, ip: str) -> Tuple[bool, int]:
        if self.is_blocked(ip):
            return False, 0
        
        now = time.time()
        if ip not in self.requests:
            self.requests[ip] = []
        
        self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window_seconds]
        current_count = len(self.requests[ip])
        
        if current_count >= self.max_requests:
            self.blocked_ips[ip] = now
            return False, current_count
        
        self.requests[ip].append(now)
        return True, current_count
    
    def reset(self, ip: str):
        if ip in self.requests:
            del self.requests[ip]
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]


class PhantomCore:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.blocking_mode = self.config.get("blocking_mode", True)
        self.sensitivity = self.config.get("sensitivity", "medium")
        
        self.rate_limiter = RateLimiter(
            max_requests=self.config.get("rate_limit", 100),
            window_seconds=60
        )
        
        self.detection_rules = []
        self.custom_rules = []
        self.whitelist = set(self.config.get("whitelist", []))
        self.blacklist = set(self.config.get("blacklist", []))
        
        self._load_default_rules()
        self.request_count = 0
        self.blocked_count = 0
        self.detection_count = 0
    
    def _load_default_rules(self):
        from detection.rules import get_default_rules
        self.detection_rules = get_default_rules(self.sensitivity)
    
    def _generate_request_id(self) -> str:
        timestamp = str(time.time())
        return hashlib.md5(timestamp.encode()).hexdigest()[:12]
    
    def _check_whitelist(self, ip: str) -> bool:
        return ip in self.whitelist
    
    def _check_blacklist(self, ip: str) -> bool:
        return ip in self.blacklist
    
    def inspect_request(self, 
                       method: str, 
                       path: str, 
                       headers: Dict[str, str],
                       body: str = "",
                       query_string: str = "",
                       source_ip: str = "127.0.0.1") -> WAFResponse:
        self.request_count += 1
        request_id = self._generate_request_id()
        
        if not self.enabled:
            return WAFResponse(
                allowed=True,
                event=None,
                status_code=200,
                message="WAF disabled - request allowed",
                request_id=request_id
            )
        
        if self._check_whitelist(source_ip):
            return WAFResponse(
                allowed=True,
                event=None,
                status_code=200,
                message="Whitelisted IP - request allowed",
                request_id=request_id
            )
        
        if self._check_blacklist(source_ip):
            event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                attack_type=AttackType.UNKNOWN.value,
                threat_level=ThreatLevel.HIGH.value,
                source_ip=source_ip,
                method=method,
                path=path,
                payload="",
                action="blocked",
                rule_id="BLACKLIST",
                request_id=request_id,
                headers=headers,
                user_agent=headers.get("User-Agent", "")
            )
            self.blocked_count += 1
            self.detection_count += 1
            return WAFResponse(
                allowed=False,
                event=event,
                status_code=403,
                message="IP address is blacklisted",
                request_id=request_id
            )
        
        allowed, request_count = self.rate_limiter.check_rate(source_ip)
        if not allowed:
            event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                attack_type=AttackType.RATE_LIMIT.value,
                threat_level=ThreatLevel.MEDIUM.value,
                source_ip=source_ip,
                method=method,
                path=path,
                payload=f"Request count: {request_count}",
                action="blocked",
                rule_id="RATE_LIMIT",
                request_id=request_id,
                headers=headers,
                user_agent=headers.get("User-Agent", "")
            )
            self.blocked_count += 1
            self.detection_count += 1
            return WAFResponse(
                allowed=False,
                event=event,
                status_code=429,
                message="Rate limit exceeded",
                request_id=request_id
            )
        
        full_request = f"{method} {path} {query_string} {body}"
        user_agent = headers.get("User-Agent", "")
        content_type = headers.get("Content-Type", "")
        
        for rule in self.detection_rules:
            match_result = rule.match(method, path, headers, body, query_string)
            if match_result.matched:
                self.detection_count += 1
                
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    attack_type=match_result.attack_type.value,
                    threat_level=match_result.threat_level.value,
                    source_ip=source_ip,
                    method=method,
                    path=path,
                    payload=match_result.matched_payload or full_request[:1000],
                    action="blocked" if self.blocking_mode else "logged",
                    rule_id=rule.rule_id,
                    request_id=request_id,
                    headers=headers,
                    user_agent=user_agent
                )
                
                if self.blocking_mode:
                    self.blocked_count += 1
                    return WAFResponse(
                        allowed=False,
                        event=event,
                        status_code=403,
                        message=f"Request blocked: {match_result.attack_type.value}",
                        request_id=request_id
                    )
                else:
                    return WAFResponse(
                        allowed=True,
                        event=event,
                        status_code=200,
                        message=f"Threat detected but allowed (monitoring mode): {match_result.attack_type.value}",
                        request_id=request_id
                    )
        
        return WAFResponse(
            allowed=True,
            event=None,
            status_code=200,
            message="Request clean",
            request_id=request_id
        )
    
    def add_custom_rule(self, rule):
        self.custom_rules.append(rule)
        self.detection_rules.append(rule)
    
    def remove_rule(self, rule_id: str):
        self.detection_rules = [r for r in self.detection_rules if r.rule_id != rule_id]
        self.custom_rules = [r for r in self.custom_rules if r.rule_id != rule_id]
    
    def whitelist_ip(self, ip: str):
        self.whitelist.add(ip)
        if ip in self.blacklist:
            self.blacklist.remove(ip)
    
    def blacklist_ip(self, ip: str):
        self.blacklist.add(ip)
        if ip in self.whitelist:
            self.whitelist.remove(ip)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_requests": self.request_count,
            "blocked_requests": self.blocked_count,
            "detections": self.detection_count,
            "active_rules": len(self.detection_rules),
            "whitelist_size": len(self.whitelist),
            "blacklist_size": len(self.blacklist),
            "rate_limited_ips": len(self.rate_limiter.blocked_ips),
            "enabled": self.enabled,
            "blocking_mode": self.blocking_mode,
            "sensitivity": self.sensitivity
        }
    
    def update_config(self, new_config: Dict):
        self.config.update(new_config)
        self.enabled = self.config.get("enabled", self.enabled)
        self.blocking_mode = self.config.get("blocking_mode", self.blocking_mode)
        
        if "sensitivity" in new_config:
            self.sensitivity = new_config["sensitivity"]
            self._load_default_rules()
        
        if "rate_limit" in new_config:
            self.rate_limiter.max_requests = new_config["rate_limit"]
        
        if "whitelist" in new_config:
            self.whitelist = set(new_config["whitelist"])
        
        if "blacklist" in new_config:
            self.blacklist = set(new_config["blacklist"])

