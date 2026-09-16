#!/bin/sh
set -e

require_config() {
    if [ ! -f /config/scraper.py ]; then
        echo "misp-scraper: no scraper.py in /config, mount the configuration volume" >&2
        exit 1
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
        echo "misp-scraper: usage: subscribe | flask | cron | cron-loop" >&2
        exit 1
        ;;
esac
