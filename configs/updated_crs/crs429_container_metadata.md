# R1.3 updated-CRS container & configuration metadata

## Image
image_ref      : owasp/modsecurity-crs:apache
image_id       : sha256:d70df2e6fecd94ad38ba815e28782c5f7c88a17bf9472576a66dfdeacada67f8
repo_digest    : owasp/modsecurity-crs@sha256:d70df2e6fecd94ad38ba815e28782c5f7c88a17bf9472576a66dfdeacada67f8

## Versions (read from inside the image / a live audit record)
crs_version    : # OWASP CRS ver.4.29.0
httpd_version  : Server version: Apache/2.4.68 (Unix)
engine_producer: ['ModSecurity for Apache/2.9.15 (http://www.modsecurity.org/)', 'OWASP_CRS/4.29.0']

## Applied configuration (from docker inspect of the running containers)
### crs-sqli  (network=host)
   ANOMALY_INBOUND=5
   ANOMALY_OUTBOUND=4
   BACKEND=http://127.0.0.1:8080
   BLOCKING_PARANOIA=1
   MODSEC_AUDIT_ENGINE=RelevantOnly
   MODSEC_REQ_BODY_ACCESS=on
   MODSEC_RESP_BODY_ACCESS=on
   MODSEC_RULE_ENGINE=on
   PORT=8081
   SSL_PORT=8444
### crs-xss  (network=host)
   ANOMALY_INBOUND=5
   ANOMALY_OUTBOUND=4
   BACKEND=http://127.0.0.1:8096
   BLOCKING_PARANOIA=1
   MODSEC_AUDIT_ENGINE=RelevantOnly
   MODSEC_REQ_BODY_ACCESS=on
   MODSEC_RESP_BODY_ACCESS=on
   MODSEC_RULE_ENGINE=on
   PORT=8086
   SSL_PORT=8445

## Reverse-proxy wiring
   crs-sqli :8081  --proxy-->  http://127.0.0.1:8080   (customapp SQLi backend, clean routes /login /search /product /filter)
   crs-xss  :8086  --proxy-->  http://127.0.0.1:8096   (php -S serving the customxss docroot: search.php, calc.php)
   All replay requests sent with HTTP header 'Host: localhost' to match the CRS-3.3.2 baseline
   (avoids CRS rule 920350 'Host header is a numeric IP address', a +3 anomaly artifact of connecting via 127.0.0.1).

## Exact docker run commands (reproducible)
   docker run -d --name crs-sqli --network host \
     -e PORT=8081 -e SSL_PORT=8444 -e BACKEND=http://127.0.0.1:8080 \
     -e BLOCKING_PARANOIA=1 -e ANOMALY_INBOUND=5 -e ANOMALY_OUTBOUND=4 \
     -e MODSEC_RULE_ENGINE=on -e MODSEC_AUDIT_ENGINE=RelevantOnly \
     -e MODSEC_AUDIT_LOG=/dev/stdout -e MODSEC_AUDIT_LOG_FORMAT=JSON -e SERVER_NAME=localhost \
     owasp/modsecurity-crs:apache
   docker run -d --name crs-xss  --network host \
     -e PORT=8086 -e SSL_PORT=8445 -e BACKEND=http://127.0.0.1:8096 \
     -e BLOCKING_PARANOIA=1 -e ANOMALY_INBOUND=5 -e ANOMALY_OUTBOUND=4 \
     -e MODSEC_RULE_ENGINE=on -e MODSEC_AUDIT_ENGINE=RelevantOnly \
     -e MODSEC_AUDIT_LOG=/dev/stdout -e MODSEC_AUDIT_LOG_FORMAT=JSON -e SERVER_NAME=localhost \
     owasp/modsecurity-crs:apache

## Baseline (unchanged host, for reference)
   Apache 2.4.52 + ModSecurity 2.9.5 + OWASP CRS 3.3.2, PL1, inbound anomaly 5 / outbound 4, blocking rule 949110.
   The host was NOT modified; the updated CRS runs in a container beside it.
