# MISP Scraper
A web scraper to create MISP events and reports

More details on the [MISP project website](https://www.misp-project.org/2022/08/08/MISP-scraper.html/).

# Prerequisites

[MISP modules installed and enabled](https://github.com/MISP/misp-modules#how-to-install-and-start-misp-modules-in-a-python-virtualenv-recommended).

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

# Submit raw HTML

Instead of scraping a site you can also submit the raw HTML via the Flask web form. The scraper will then strip the HTML and convert it to MarkDown. It is then added as a MISP report, after which the attributes and context elements are extracted. For existing setups, install `markdownify` in the venv.

This is the first step to using another 'scraper' instead of the regular Python requests - https://github.com/cudeso/misp-scraper/issues/6 .

# Automatically delete scraped attributes

Some elements from the scraped web site are not useful to be added as a MISP attribute, for example 'Zone.Identifier' and 'http://google.com/ads/remarketingsetup'. 

After scraping a website, the scraper reads the entries from one warninglist (defined via **misp_warninglist** in the config) and then (either hard or soft- **misp_hard_delete_on_cleanup**) deletes the matching attributes from the newly created MISP event. This avoids that you repeatedly have to delete the same attributes over and over from newly created events.

The warninglist needs to be of **string** type. Do not forget to enable this warninglist.

# Screenshots

![misp-scraper-Components.drawio.png](assets/misp-scraper-Components.drawio.png)

![misp-scraper-Workflow.drawio.png](assets/misp-scraper-Workflow.drawio.png)

![misp-scraper-events.png](assets/misp-scraper-events.png)

![misp-scraper-tags.png](assets/misp-scraper-tags.png)

![misp-scraper-manual.png](assets/misp-scraper-manual.png)