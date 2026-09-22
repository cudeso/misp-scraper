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

## Behind a proxy

`pip install` failing with `Network is unreachable` means the build container has cannot connect externally. The builder ignores your shell environment and reads the Docker client configuration instead, so put the proxy setup in `~/.docker/config.json`:

```json
{
  "proxies": {
    "default": {
      "httpProxy": "http://proxy.example.com:8080",
      "httpsProxy": "http://proxy.example.com:8080",
      "noProxy": "localhost,127.0.0.1,::1,.example.com"
    }
  }
}
```

Be aware:

- `sudo docker compose build` reads the configuration of root, not yours.
- `http_proxy` in `/etc/environment` or in your shell has no impact for the build.
- If it already fails while pulling `python:3.12-slim`, the daemon needs its own proxy in `/etc/docker/daemon.json`, and a `systemctl restart docker`.
- A proxy that inspects TLS gives certificate errors rather than `Network is unreachable`. Copy its CA into `/usr/local/share/ca-certificates`, run `update-ca-certificates` before the `pip install` line, and point `PIP_CERT`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` at `/etc/ssl/certs/ca-certificates.crt`. pip, pymisp and curl_cffi each carry their own bundle and won't look at the system store otherwise. `pip --trusted-host` is not a fix.
- The containers get no proxy variables of their own. If the scraper can't reach the sites it fetches, add `http_proxy`, `https_proxy` and `no_proxy` to `environment:`, with the MISP host and `127.0.0.1` in `no_proxy`.

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
