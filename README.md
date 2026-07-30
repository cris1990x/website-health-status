# Website Health Status

Automated daily read-only health checks for Wealth Excel marketing sites.

- **Live data for GHL:** `https://cdn.jsdelivr.net/gh/cris1990x/website-health-status@main/data.json`
- **Status page:** `https://wealthexcel-marketupdate.mcmcrm.com/website-health-status-page`

## Automation

GitHub Actions runs every day at **8:00 AM Eastern (EDT)** (`0 12 * * *` UTC), updates `data.json`, and purges the jsDelivr cache so the GHL page refreshes automatically.

Manual run: **Actions → Daily website health check → Run workflow**

## Local run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python health_check.py
cp dashboard/data.json data.json
```
