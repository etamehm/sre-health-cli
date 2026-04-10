# sre-health-cli

Lightweight CLI tool for checking service health - HTTP status, response time, and SSL certificate expiry.

Built for SRE and platform teams who need a quick, scriptable way to verify endpoint health without spinning up a full monitoring stack.

## What it does

- Checks HTTP status codes and response times
- Checks SSL certificate expiry (days remaining)
- Reads targets from a simple YAML config
- Outputs as a readable table or Prometheus-compatible metrics

## Quick start

```bash
pip install -r requirements.txt
python healthcheck.py
```

## Configuration

Edit `config.yaml` to add your endpoints:

```yaml
targets:
  - name: My API
    url: https://api.example.com/health
    timeout: 5
    check_ssl: true
```

## Output formats

**Table (default):**
```
$ python healthcheck.py

Checking 3 targets...

NAME                 STATUS  RESP(ms)   SSL EXPIRY  SSL DAYS ERROR
----------------------------------------------------------------------
Google                  200        85   2026-10-15       188
GitHub                  200       120   2026-09-01       144
Example (HTTP)          200        45            -         -
```

**Prometheus metrics:**
```
$ python healthcheck.py --format prometheus

# HELP health_check_status HTTP status code (0 = failed)
# TYPE health_check_status gauge
health_check_status{name="Google",url="https://www.google.com"} 200
health_check_response_ms{name="Google",url="https://www.google.com"} 85
health_check_ssl_days_left{name="Google",url="https://www.google.com"} 188
```

## Usage

```
python healthcheck.py                        # default table output
python healthcheck.py --format prometheus    # prometheus metrics
python healthcheck.py --config custom.yaml   # custom config file
```

## Roadmap

- [ ] v0.2: Alerting thresholds (warn if response > Xms, SSL < Y days)
- [ ] v0.3: Serve as Prometheus exporter (HTTP `/metrics` endpoint)
- [ ] v0.4: Kubernetes liveness/readiness probe integration
- [ ] v0.5: Slack/webhook notifications on failures

## Why I built this

I've spent years running platform health checks manually or with heavyweight tools. This is the quick, scriptable version I always wanted - something you can run from a cron job, a CI pipeline, or just your terminal.

## License

MIT
