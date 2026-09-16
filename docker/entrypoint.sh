#!/bin/sh
set -e

# Config errors do not fix themselves on restart, so fail on them here with one
# readable line instead of letting the restart policy loop on a traceback.
require_config() {
    if [ ! -f /config/scraper.py ]; then
        echo "misp-scraper: no scraper.py in /config, mount the configuration volume" >&2
        exit 1
    fi

    python - <<'PY' || exit 1
import sys

try:
    import scraper
except Exception as e:
    sys.exit("misp-scraper: cannot read /config/scraper.py: {}".format(e))

missing = [n for n in ("misp_url", "misp_key") if not str(getattr(scraper, n, "")).strip()]
if missing:
    sys.exit("misp-scraper: set {} in /config/scraper.py".format(" and ".join(missing)))
PY
}

case "$1" in
    subscribe|flask|cron)
        require_config
        exec python /app/misp-scraper.py "$1"
        ;;
    cron-loop)
        require_config
        while true; do
            python /app/misp-scraper.py cron || echo "misp-scraper: cron run failed" >&2
            sleep "${CRON_INTERVAL:-3600}"
        done
        ;;
    *)
        echo "misp-scraper: usage: subscribe | flask | cron | cron-loop" >&2
        exit 1
        ;;
esac
