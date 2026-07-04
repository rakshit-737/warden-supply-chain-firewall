"""Analyzer registry."""

from app.analysis.analyzers.base import Analyzer, PackageContext
from app.analysis.analyzers.install_script import InstallScriptAnalyzer
from app.analysis.analyzers.ioc import IOCAnalyzer
from app.analysis.analyzers.metadata import MetadataAnalyzer
from app.analysis.analyzers.obfuscation import ObfuscationAnalyzer
from app.analysis.analyzers.static_code import StaticCodeAnalyzer
from app.analysis.analyzers.typosquat import TyposquatAnalyzer

# Order is informational only; analyzers are independent.
ALL_ANALYZERS: list[Analyzer] = [
    MetadataAnalyzer(),
    TyposquatAnalyzer(),
    StaticCodeAnalyzer(),
    InstallScriptAnalyzer(),
    ObfuscationAnalyzer(),
    IOCAnalyzer(),
]

__all__ = ["Analyzer", "PackageContext", "ALL_ANALYZERS"]
