#!/bin/bash
echo "===== run bwApp install (creates the bWAPP database + tables) ====="
curl -s -o /tmp/bwapp_install_out.html -w "install.php?install=yes -> HTTP %{http_code}\n" --max-time 30 "http://127.0.0.1:8082/install.php?install=yes"
grep -oiE "successfully|installation|created|error|already" /tmp/bwapp_install_out.html 2>/dev/null | sort -u | head
sleep 3
echo "===== re-test: login + a product query ====="
curl -s -c /tmp/bwapp_cookies.txt -o /dev/null "http://127.0.0.1:8082/login.php"
curl -s -b /tmp/bwapp_cookies.txt -c /tmp/bwapp_cookies.txt -o /dev/null \
  --data "login=bee&password=bug&security_level=0&form=submit" "http://127.0.0.1:8082/login.php"
echo -n "sqli_3.php (login challenge) renders SQL Injection: "
curl -s -b /tmp/bwapp_cookies.txt "http://127.0.0.1:8082/sqli_3.php" | grep -qi "SQL Injection" && echo YES || echo NO
echo -n "sqli_1.php (search) renders: "
curl -s -b /tmp/bwapp_cookies.txt "http://127.0.0.1:8082/sqli_1.php?title=iron&action=search" | grep -qiE "iron|movie|</tr>" && echo YES || echo NO
