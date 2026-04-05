"""
PhantomWall Detection Module
"""

from .rules import (
    DetectionRule,
    SQLInjectionRule,
    XSSRule,
    CommandInjectionRule,
    PathTraversalRule,
    CSRFRule,
    FileInclusionRule,
    SensitiveDataRule,
    MatchResult,
    get_default_rules
)

__all__ = [
    "DetectionRule",
    "SQLInjectionRule",
    "XSSRule",
    "CommandInjectionRule",
    "PathTraversalRule",
    "CSRFRule",
    "FileInclusionRule",
    "SensitiveDataRule",
    "MatchResult",
    "get_default_rules"
]
