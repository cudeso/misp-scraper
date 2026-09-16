FROM python:3.12-slim

# The volume at /config holds scraper.py, feedlist.json and the log. /app has no
# scraper.py, so "from scraper import *" falls through to PYTHONPATH.
ENV PYTHONPATH=/config \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY misp-scraper.py ./
COPY templates/ ./templates/
COPY docker/entrypoint.sh /usr/local/bin/

# Must match the owner of the volume, or the log file cannot be written.
ARG UID=1000
RUN chmod +x /usr/local/bin/entrypoint.sh && useradd --no-create-home --uid "$UID" scraper
USER scraper

ENTRYPOINT ["entrypoint.sh"]
CMD ["subscribe"]
