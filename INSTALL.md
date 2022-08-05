git clone https://github.com/cudeso/misp-scraper
cd misp-scraper
virtualenv scraper
source scraper/bin/active
pip install -r requirements
cp scraper.py.default scraper.py