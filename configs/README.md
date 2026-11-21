# Configuration

The actual configuration files from the experiment host, copied verbatim. Nothing
here is a reconstruction or a template. Each was scanned for credentials before
being committed; none contained any.

## `modsecurity/`

| File | What it is |
| --- | --- |
| `modsecurity.conf` | The ModSecurity engine configuration. `SecRuleEngine` is On, so the WAF blocks rather than only logging. |
| `security2.conf` | The Apache module hook. This is the file that decides what gets loaded, and in what order: the engine config, then the CRS bundle, then `/etc/modsecurity/custom/*.conf`. |
| `00-genwebsec-proxy.conf` | The reverse-proxy map. Sends `/customapp/` to port 8080, `/juice/` to 3000, and `/bwapp/` to 8082. Because every target sits behind the same proxy, all three are inspected by one identical WAF configuration. |
| `000-default.conf` | The Apache virtual host on port 80. |
| `ports.conf` | Apache listen directives. |

## `crs/`

| File | What it is |
| --- | --- |
| `crs-setup.conf` | The stock OWASP CRS 4.29.0 setup file, copied verbatim from the `owasp/modsecurity-crs:apache` container image used for the reported runs. Runtime options (paranoia level 1, inbound/outbound anomaly thresholds of 5 and 4, blocking mode) are set through the container's environment variables, not by editing this file; the variables and the exact `docker run` commands are in `../updated_crs/crs429_container_metadata.md`. |

The CRS rule files themselves are not copied here. They are the unmodified OWASP
CRS 4.29.0 rules shipped in the container image, pinned exactly by the image
digest recorded in `../updated_crs/crs429_container_metadata.md`; a digest pull
reproduces them exactly, so copying tens of thousands of lines of third-party
rules here would add nothing.

**No CRS rule exclusions were used.** The baseline is stock CRS.

## The generated-rule include

The defense agent writes its accepted rules to a single file:

```
/etc/modsecurity/custom/sft_rule.conf
```

which is picked up by the `IncludeOptional /etc/modsecurity/custom/*.conf`
directive in `security2.conf`. An **empty** file is the CRS-only baseline
condition. Before every Apache reload the harness runs the configuration test,
and a candidate rule that fails it is discarded instead of deployed.

That filename is inherited from an earlier project and says nothing about the
rules it holds. The code that writes it is `helpers/modsec_helpers.py`.

The generated rules themselves are not configuration; they are experimental
output and live under `rules/`.

## `experiment/`

Not yet populated. The machine-readable per-experiment parameters, covering batch
sizes, temperature allocation, seeds, budgets, thresholds, clustering settings,
and grouping strategy, are added in a later step of the artifact build.
