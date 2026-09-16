# misp-scraper in Docker

The image supports three commands: `subscribe` (long-running), `cron` (runs once), `cron-loop` (`cron` every `CRON_INTERVAL` seconds). `flask` works too but has no compose service.

Redis is not part of this stack. The containers connect to a redis server that already runs on the host, and use `network_mode: host` to reach it on `127.0.0.1`.

## Setup

```
cd docker
mkdir -p config
cp scraper.py.docker config/scraper.py
cp ../feedlist.json config/feedlist.json
cp env.example .env
```

Set `misp_url` and `misp_key` in `config/scraper.py`, and `REDIS_PASSWORD` in `.env` to the password of the existing redis. For a redis on another host set `REDIS_HOST` and `REDIS_PORT` as well.

The entrypoint checks that `config/scraper.py` imports and that `misp_url` and
`misp_key` are set.

The container writes `config/scraper.log` as UID 1000. If that is not you:

```
docker compose build --build-arg UID=$(id -u)
```

## Run

```
docker compose up -d --build
tail -f config/scraper.log
```

Scrape without waiting for `CRON_INTERVAL`:

```
docker compose run --rm cron cron
```

That is the equivalent of `misp-scraper.py cron` outside Docker. It runs in its own container, logs to the same `config/scraper.log`, and exits when the run is done. The `cron` service keeps running on its schedule meanwhile. Add `subscribe` or `flask` in place of the second `cron` to run those one-off.

## zsazsa

Don't know what zsazsa is? zsazsa is a CTI program management and production platform built around MISP, see: [https://zsazsa-project.org/](https://zsazsa-project.org/). Point it at the same redis with the same password:

```
SCRAPER_REDIS_HOST=<redis host>
SCRAPER_REDIS_PORT=6379
SCRAPER_REDIS_PASSWORD=<REDIS_PASSWORD>
SCRAPER_REDIS_CHANNEL=urls
```

`SCRAPER_MARKER_TAG` must match a tag this scraper sets.

## Gotchas

- `network_mode: host` means the containers use the host network directly. No ports are published
- Config is via `PYTHONPATH=/config`. Never bind-mount over `/app`.
- `scraper.py.docker` is `scraper.py.default` with the log and feedlist pointed into the volume and redis read from the environment.
- No log rotation. Point logrotate at `config/scraper.log` if you run at debug level.
