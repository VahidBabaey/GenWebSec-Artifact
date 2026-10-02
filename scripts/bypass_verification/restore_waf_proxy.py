#!/usr/bin/env python3
"""Restore sft_rule.conf to proxy-only (SecAuditEngine reverts to Off from modsecurity.conf)."""
import sys
sys.path.insert(0, "/home/vahid/Projects/GenWebSec")
from helpers.modsec_helpers import write_rules, run_configtest, reload_apache
PROXY = [
    "ProxyPass        /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPassReverse /customxss/search.php http://127.0.0.1:8094/search.php",
    "ProxyPass        /customxss/calc.php http://127.0.0.1:8095/calc.php",
    "ProxyPassReverse /customxss/calc.php http://127.0.0.1:8095/calc.php",
]
write_rules(PROXY)
print("configtest", run_configtest()[0])
print("reload", reload_apache(timeout=30)[0])
