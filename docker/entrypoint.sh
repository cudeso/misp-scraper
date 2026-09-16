#!/bin/sh
set -e

# A bad configuration does not fix itself on restart. The compose services use
# restart: on-failure, which leaves a container alone once it exits 0, so the checks
# below report the problem and exit 0 deliberately rather than looping forever.
config_error() {
    echo "misp-scraper: not starting until the configuration is fixed" >&2
    exit 0
}

require_config() {
    if [ ! -f /config/scraper.py ]; then
        echo "misp-scraper: no scraper.py in /config, mount the configuration volume" >&2
        config_error
    fi

    if ! python - <<'PY'
import sys

try:
    import scraper
except Exception as e:
    sys.exit("misp-scraper: cannot read /config/scraper.py: {}".format(e))

missing = [n for n in ("misp_url", "misp_key") if not str(getattr(scraper, n, "")).strip()]
if missing:
    sys.exit("misp-scraper: set {} in /config/scraper.py".format(" and ".join(missing)))
PY
    then
        config_error
    fi
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
        # Not exit 0: the compose services pass a fixed command, so this is someone
        # running the image by hand and wanting a real exit status.
        echo "misp-scraper: usage: subscribe | flask | cron | cron-loop" >&2
        exit 1
        ;;
esac
