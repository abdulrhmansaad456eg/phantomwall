import re
from dataclasses import dataclass
from typing import Dict, Pattern, Optional, List
from enum import Enum


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


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MatchResult:
    matched: bool
    attack_type: AttackType
    threat_level: ThreatLevel
    matched_payload: Optional[str] = None
    description: str = ""


class DetectionRule:
    def __init__(self, 
                 rule_id: str,
                 name: str,
                 attack_type: AttackType,
                 threat_level: ThreatLevel,
                 patterns: List[str],
                 description: str = ""):
        self.rule_id = rule_id
        self.name = name
        self.attack_type = attack_type
        self.threat_level = threat_level
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.description = description
    
    def match(self, method: str, path: str, headers: Dict[str, str], body: str, query: str) -> MatchResult:
        targets = [
            path,
            query,
            body,
            headers.get("X-Forwarded-For", "")
        ]
        
        for target in targets:
            if not target:
                continue
            for pattern in self.patterns:
                match = pattern.search(target)
                if match:
                    return MatchResult(
                        matched=True,
                        attack_type=self.attack_type,
                        threat_level=self.threat_level,
                        matched_payload=match.group(0),
                        description=self.description
                    )
        
        return MatchResult(matched=False, attack_type=self.attack_type, threat_level=self.threat_level)


class SQLInjectionRule(DetectionRule):
    def __init__(self, sensitivity: str = "medium"):
        base_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec\s*\(\s*\+",
            r"UNION\s+SELECT",
            r"INSERT\s+INTO",
            r"DELETE\s+FROM",
            r"DROP\s+TABLE",
            r"ALTER\s+TABLE",
            r"SELECT\s+.*\s+FROM",
            r"WAITFOR\s+DELAY",
            r"BENCHMARK\s*\(",
            r"SLEEP\s*\(",
            r"1\s*=\s*1",
            r"1\s*=\s*2",
            r"'\s*OR\s*'1",
            r"'\s*AND\s*1\s*=\s*1",
            r";\s*shutdown",
            r";\s*drop",
            r"union\s+select.*from",
            r"load_file\s*\(",
            r"into\s+outfile",
            r"information_schema",
            r"sysdatabases",
            r"sysobjects"
        ]
        
        if sensitivity == "high":
            base_patterns.extend([
                r"(\%27)|(\')",
                r"\d+\s*=\s*\d+",
                r"OR\s+\d+\s*=\s*\d+",
                r"AND\s+\d+\s*=\s*\d+"
            ])
        
        super().__init__(
            rule_id="SQLI-001",
            name="SQL Injection Detection",
            attack_type=AttackType.SQL_INJECTION,
            threat_level=ThreatLevel.CRITICAL,
            patterns=base_patterns,
            description="Detects SQL injection attempts in request parameters"
        )


class XSSRule(DetectionRule):
    def __init__(self, sensitivity: str = "medium"):
        base_patterns = [
            r"((\%3C)|<)[^\n]+((\%3E)|>)",
            r"((\%3C)|<)\s*script",
            r"((\%3C)|<)\s*img[^>]+src",
            r"javascript\s*:",
            r"on\w+\s*=",
            r"<\s*script\s*>",
            r"</\s*script\s*>",
            r"alert\s*\(",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
            r"eval\s*\(",
            r"expression\s*\(",
            r"<\s*iframe",
            r"<\s*object",
            r"<\s*embed",
            r"src\s*=\s*['\"]\s*javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<\s*body[^>]*background",
            r"<\s*input[^>]*type\s*=\s*['\"]\s*image",
            r"<\s*link[^>]*rel\s*=\s*['\"]\s*stylesheet"
        ]
        
        if sensitivity == "high":
            base_patterns.extend([
                r"<\s*\w+",
                r"\Wstyle\s*=",
                r"data:\s*text/html"
            ])
        
        super().__init__(
            rule_id="XSS-001",
            name="Cross-Site Scripting Detection",
            attack_type=AttackType.XSS,
            threat_level=ThreatLevel.HIGH,
            patterns=base_patterns,
            description="Detects XSS attack patterns in request data"
        )


class CommandInjectionRule(DetectionRule):
    def __init__(self, sensitivity: str = "medium"):
        base_patterns = [
            r";\s*(cat|ls|pwd|whoami|id|uname|nc|netcat|wget|curl|python|perl|ruby|php|bash|sh|cmd|powershell)\s",
            r"\|\s*(cat|ls|pwd|whoami|id|uname|nc|netcat|wget|curl|python|perl|ruby|php|bash|sh|cmd|powershell)\s",
            r"&&\s*(cat|ls|pwd|whoami|id|uname|nc|netcat|wget|curl|python|perl|ruby|php|bash|sh|cmd|powershell)\s",
            r"\$\(\s*(cat|ls|pwd|whoami|id|uname|nc|wget|curl)",
            r"`\s*(cat|ls|pwd|whoami|id|uname)`",
            r"bin\s*/bash",
            r"bin\s*/sh",
            r"cmd\.exe",
            r"powershell",
            r"nc\s+-[l|e]",
            r"netcat",
            r"wget\s+http",
            r"curl\s+http",
            r"python\s+-[c|m]",
            r"perl\s+-e",
            r"ruby\s+-e",
            r"php\s+-r",
            r"system\s*\(",
            r"exec\s*\(",
            r"eval\s*\(",
            r"popen\s*\("
        ]
        
        super().__init__(
            rule_id="CMDI-001",
            name="Command Injection Detection",
            attack_type=AttackType.COMMAND_INJECTION,
            threat_level=ThreatLevel.CRITICAL,
            patterns=base_patterns,
            description="Detects command injection attempts"
        )


class PathTraversalRule(DetectionRule):
    def __init__(self, sensitivity: str = "medium"):
        base_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"\.\.//",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
            r"%c0%ae%c0%ae%c0%af",
            r"\.\.\.%2f",
            r"%2e%2e/",
            r"%252e%252e/",
            r"\.{3,}",
            r"etc/passwd",
            r"etc\\passwd",
            r"windows\\system32",
            r"win\.ini",
            r"boot\.ini",
            r"..\\..\\",
            r"..%5c",
            r"%5c..",
            r"\\\\.*\\",
            r"/etc/shadow",
            r"/proc/self",
            r"../../../../",
            r"....//",
            r"....\\"
        ]
        
        super().__init__(
            rule_id="PT-001",
            name="Path Traversal Detection",
            attack_type=AttackType.PATH_TRAVERSAL,
            threat_level=ThreatLevel.HIGH,
            patterns=base_patterns,
            description="Detects path traversal and LFI attempts"
        )


class CSRFRule(DetectionRule):
    def __init__(self, sensitivity: str = "medium"):
        self.sensitivity = sensitivity
        super().__init__(
            rule_id="CSRF-001",
            name="CSRF Detection",
            attack_type=AttackType.CSRF,
            threat_level=ThreatLevel.MEDIUM,
            patterns=[],
            description="Checks for CSRF protection headers"
        )
    
    def match(self, method: str, path: str, headers: Dict[str, str], body: str, query: str) -> MatchResult:
        if method not in ["POST", "PUT", "DELETE", "PATCH"]:
            return MatchResult(matched=False, attack_type=self.attack_type, threat_level=self.threat_level)
        
        referer = headers.get("Referer", "")
        origin = headers.get("Origin", "")
        x_requested_with = headers.get("X-Requested-With", "")
        content_type = headers.get("Content-Type", "")
        
        has_protection = bool(
            x_requested_with or
            (origin and not origin.startswith("http://localhost")) or
            (referer and not referer.startswith("http://localhost")) or
            (content_type and "application/json" in content_type)
        )
        
        if self.sensitivity == "high" and not has_protection:
            return MatchResult(
                matched=True,
                attack_type=self.attack_type,
                threat_level=ThreatLevel.LOW,
                description="Request lacks CSRF protection headers"
            )
        
        return MatchResult(matched=False, attack_type=self.attack_type, threat_level=self.threat_level)


class FileInclusionRule(DetectionRule):
    def __init__(self, sensitivity: str = "medium"):
        base_patterns = [
            r"(include|require)(_once)?\s*\(?\s*['\"]",
            r"php://filter",
            r"php://input",
            r"data://text/plain",
            r"expect://",
            r"file://",
            r"http://\w+.*\?.*=",
            r"https://\w+.*\?.*=",
            r"ftp://",
            r"sftp://",
            r"\?file=",
            r"\?page=",
            r"\?include=",
            r"\?document=",
            r"\?path=",
            r"\?folder=",
            r"\?root=",
            r"\?pg=",
            r"\?style=",
            r"\?template=",
            r"\?phpbb_root_path=",
            r"\?template_path=",
            r"\?module=",
            r"\?mod=",
            r"\?conf=",
            r"\?config=",
            r"\?loc=",
            r"\?location=",
            r"\?show=",
            r"\?view="
        ]
        
        super().__init__(
            rule_id="FI-001",
            name="File Inclusion Detection",
            attack_type=AttackType.FILE_INCLUSION,
            threat_level=ThreatLevel.HIGH,
            patterns=base_patterns,
            description="Detects local and remote file inclusion attempts"
        )


class SensitiveDataRule(DetectionRule):
    def __init__(self, sensitivity: str = "medium"):
        base_patterns = [
            r"password\s*=\s*['\"][^'\"]{1,20}['\"]",
            r"passwd\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
            r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]",
            r"private[_-]?key\s*=\s*['\"][^'\"]+['\"]",
            r"aws_access_key_id\s*=\s*['\"][A-Z0-9]{20}['\"]",
            r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
            r"AKIA[0-9A-Z]{16}",
            r"[0-9a-f]{32}-us[0-9]{2}",
            r"sk_live_[0-9a-zA-Z]{24,}",
            r"sk_test_[0-9a-zA-Z]{24,}",
            r"pk_live_[0-9a-zA-Z]{24,}",
            r"pk_test_[0-9a-zA-Z]{24,}",
            r"BEGIN\s+(RSA\s+)?PRIVATE\s+KEY",
            r"BEGIN\s+DSA\s+PRIVATE\s+KEY",
            r"BEGIN\s+EC\s+PRIVATE\s+KEY",
            r"BEGIN\s+OPENSSH\s+PRIVATE\s+KEY",
            r"ssn\s*=\s*['\"]?\d{3}-\d{2}-\d{4}['\"]?",
            r"credit[_-]?card\s*=\s*['\"]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}['\"]?",
            r"\b4[0-9]{12}(?:[0-9]{3})?\b",
            r"\b5[1-5][0-9]{14}\b",
            r"\b3[47][0-9]{13}\b"
        ]
        
        super().__init__(
            rule_id="SDE-001",
            name="Sensitive Data Exposure",
            attack_type=AttackType.SENSITIVE_DATA_EXPOSURE,
            threat_level=ThreatLevel.MEDIUM,
            patterns=base_patterns,
            description="Detects potential sensitive data in request/response"
        )


def get_default_rules(sensitivity: str = "medium") -> List[DetectionRule]:
    return [
        SQLInjectionRule(sensitivity),
        XSSRule(sensitivity),
        CommandInjectionRule(sensitivity),
        PathTraversalRule(sensitivity),
        CSRFRule(sensitivity),
        FileInclusionRule(sensitivity),
        SensitiveDataRule(sensitivity)
    ]
