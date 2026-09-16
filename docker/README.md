# misp-scraper in Docker

The Flask component is not yet part of Docker.

## Setup

```
cd docker
mkdir -p config
cp scraper.py.docker config/scraper.py
cp ../feedlist.json config/feedlist.json
cp env.example .env
```

Set `misp_url` and `misp_key` in `config/scraper.py`, `REDIS_PASSWORD` in `.env`.
Both redis and the scraper read that same variable.

The container writes `config/scraper.log` as UID 1000. If that is not you:

```
docker compose build --build-arg UID=$(id -u)
```

## Run

```
docker compose up -d --build
tail -f config/scraper.log
```

One-off feed pull, outside the schedule:

```
docker compose run --rm cron cron
```

Nothing retries. Unreachable MISP or redis means the container exits and restarts, so
a few restarts at boot are normal. `docker compose logs` has those; everything else is
in `config/scraper.log`.

## zsazsa

Point it at the published redis port with the same password:

```
SCRAPER_REDIS_HOST=<docker host>
SCRAPER_REDIS_PORT=6379
SCRAPER_REDIS_PASSWORD=<REDIS_PASSWORD>
SCRAPER_REDIS_CHANNEL=urls
```

Redis binds to `127.0.0.1`. For zsazsa on another host set `REDIS_BIND=0.0.0.0` in
`.env` and firewall the port, the password is the only protection.

`SCRAPER_MARKER_TAG` must match a tag this scraper sets. Defaults differ
(`zsazsa:source="misp-scraper"` vs `curation:source="misp-scraper"` in
`misp_scraper_tags_local`), so change one or nothing is collected.

## Gotchas

- Config is found via `PYTHONPATH=/config`. Never bind-mount over `/app`, a
  `scraper.py` there wins.
- `scraper.py.docker` is `scraper.py.default` with the log, feedlist and redis
  password pointed at the volume and environment. Keep both in step: the scraper does
  `from scraper import *`, a missing setting results in an import error.
- No log rotation.
