git clone https://github.com/cudeso/misp-scraper
cd misp-scraper
virtualenv scraper
source scraper/bin/activate
pip install -r requirements.txt
cp scraper.py.default scraper.py

Set misp_url and misp_key in scraper.py. The MISP user of the API key needs a role with the Tagger and Tag Editor permissions, otherwise no tags are added to the events.
