# Coraza and OWASP CRS in the ERP testbed

Caddy terminates HTTPS. Its Coraza module checks ERP requests before the reverse proxy sends them to Flask. The login request size check runs first. The Caddy health-test and internal routes keep their existing handlers.

The build uses Caddy 2.11.9 and the Apache-2.0 Coraza Caddy module v2.6.2, which embeds Coraza 3.8.1 and OWASP CRS 4.25.0. The build script adapts the module's logging to the capstone's data policy. Upstream source: https://github.com/corazawaf/coraza-caddy/tree/v2.6.2

The default `CORAZA_RULE_ENGINE=DetectionOnly` records SQL injection (`942xxx`) and XSS (`941xxx`) matches and passes requests onward. In `On` mode, the CRS inbound score threshold is 5 and the blocking evaluation can return 403 before ERP. The isolated Caddy endpoint uses an IP address as its Host, so the numeric-Host CRS rule 920350 is disabled for this endpoint.

| Container file | Record |
| --- | --- |
| Caddy `/var/log/caddy/access.json` | Request ID, client IP, path, method, and final response status. |
| Caddy `/var/log/caddy/waf.jsonl` | Caddy-generated request ID, client IP, numeric matched rule IDs, inbound score and blocking status. The writer does not serialize request headers, request bodies, query strings, or matched inputs. |
| Caddy converter `/out/caddy.jsonl` | Existing observation stream, with `waf_detected` or `waf_blocked` events from the WAF file and the existing size-limit events from the access file. |
| ERP `/var/log/erp/erp.jsonl` | Events handled by ERP. A request blocked before proxying cannot produce an ERP event for that request ID. |

The live collector reads the existing observation stream. In the WAF tab, the CRS rule IDs and the Caddy request ID identify the reason and let operators match the entry to the access log. The suspicious input is not stored as evidence.

After recreating the Caddy container, rerun the existing `route-caddy` Compose service and wait for exit code 0 before testing client access. The route belongs to Caddy's network namespace and is lost on container recreation. The default `DetectionOnly` mode is restored after a temporary `On` mode test by recreating Caddy without the override, followed by `route-caddy` again.
