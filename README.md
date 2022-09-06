# MISP Scraper
A web scraper to create MISP events and reports

More details on the [MISP project website](https://www.misp-project.org/2022/08/08/MISP-scraper.html/).

# Install

```
git clone https://github.com/cudeso/misp-scraper
cd misp-scraper
virtualenv scraper
source scraper/bin/activate
pip install -r requirements.txt
cp scraper.py.default scraper.py
```

Then install and enable the service scripts (change the path /home/ubuntu to your MISP user).
Run the cron job.

# Screenshots

![misp-scraper-Components.drawio.png](assets/misp-scraper-Components.drawio.png)

![misp-scraper-Workflow.drawio.png](assets/misp-scraper-Workflow.drawio.png)

![misp-scraper-events.png](assets/misp-scraper-events.png)

![misp-scraper-tags.png](assets/misp-scraper-tags.png)

![misp-scraper-manual.png](assets/misp-scraper-manual.png)