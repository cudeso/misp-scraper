import feedparser
import logging
import os
import json
import redis
import sys
from pymisp import *
import urllib3
from urllib import parse
import requests
from curl_cffi import requests as cf_requests
from bs4 import BeautifulSoup
from markdownify import markdownify
import html
import time
import re
from flask import Flask, render_template, request, url_for, flash, redirect
sys.path.insert(0, "/var/www/MISP/misp-custom/scripts/misp-scraper")
from urllib.parse import urlparse
from scraper import *


class MispScraperFeedparser():
    def __init__(self) -> None:
        config = MispScraperConfig()
        self.config = config

        self.feed_list: dict
        self.url_list: dict

        self.feed_list = []
        self.url_list = []

    def _get_urls_feed(self, rss_feed, rss_feed_title, rss_feed_tags) -> dict:
        """ Get all the URLs contained in a feed"""
        urls = []
        if rss_feed:
            started = time.monotonic()
            try:
                parsed_feed_url = urlparse(rss_feed)
                if parsed_feed_url.scheme in ["http", "https"]:
                        # Try curl_cffi first. Fall back to plain requests.
                        try:
                            response = cf_requests.get(rss_feed, impersonate="chrome124", timeout=30)
                            response.raise_for_status()
                            rss_feed_content = feedparser.parse(response.content)
                        except Exception as curl_err:
                            logging.warning("curl_cffi failed for {}, retrying with requests: {}".format(rss_feed, curl_err))
                            _headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"}
                            response = requests.get(rss_feed, timeout=30, headers=_headers)
                            response.raise_for_status()
                            rss_feed_content = feedparser.parse(response.content)
                else:
                    rss_feed_content = feedparser.parse(rss_feed)
                if not rss_feed_content.bozo:
                    if len(rss_feed_content) > 0:
                        feed_entries = len(rss_feed_content)
                        for entry in rss_feed_content.entries:
                            title = entry.get('title', 'No title')
                            link = entry.get('link', False)
                            published = entry.get('published', False)
                            if link:
                                if not published:
                                    published = "1970-01-01T00:00:00 +0000"
                                logging.debug("Found URL {} {} {}".format(rss_feed, title, link))
                                urls.append({"feed_title": rss_feed_title, "feed": rss_feed, "title": title, "link": link, "published": published, "feed_tags": rss_feed_tags})
                else:
                    # The RSS feed has malformed XML; still try to extract some URLs
                    if len(rss_feed_content) > 0:
                        for entry in rss_feed_content.entries:
                            title = entry.get('title', 'No title')
                            link = entry.get('link', False)
                            published = entry.get('published', False)
                            if link:
                                if not published:
                                    published = "1970-01-01T00:00:00 +0000"
                                logging.debug("Found URL - despite malformed XML- {} {} {}".format(rss_feed, title, link))
                                urls.append({"feed_title": rss_feed_title, "feed": rss_feed, "title": title, "link": link, "published": published, "feed_tags": rss_feed_tags})

                    bozo_exception = rss_feed_content.get('bozo_exception', '')
                    logging.error("Error when parsing RSS data for {} {}".format(rss_feed, bozo_exception))
                logging.info("Fetched RSS feed {} in {:.2f}s with {} URL(s)".format(rss_feed, time.monotonic() - started, len(urls)))
            except requests.exceptions.Timeout:
                logging.error("Timeout when accessing RSS feed {}".format(rss_feed))
            except requests.exceptions.RequestException as e:
                logging.error("HTTP error when accessing RSS feed {} {}".format(rss_feed, e))
            except Exception as e:
                logging.error("Error when accessing RSS feed {} {}".format(rss_feed, e))
        return urls

    def _get_rss(self) -> dict:
        """ Internal function. Loads the RSS data per feed. """
        feeds = []
        if len(self.feed_list) > 0:
            total = len(self.feed_list)
            for index, feed in enumerate(self.feed_list, start=1):
                logging.info("Processing feed {}/{}: {}".format(index, total, feed.get("url", "unknown")))
                logging.debug("Parse feed {}".format(feed))
                r = self._get_urls_feed(feed["url"], feed["title"], feed["tags"])
                feeds = feeds + r
        return feeds

    def get_urls(self) -> dict:
        """ Returns the list of URLs """
        return self.url_list

    def fetch_rss(self) -> bool:
        """ Load the RSS data, and get all the URLs contained in the RSS data """
        if len(self.feed_list) > 0:
            started = time.monotonic()
            logging.info("Starting RSS fetch for {} feed(s)".format(len(self.feed_list)))
            self.url_list = self._get_rss()
            logging.info("Finished RSS fetch in {:.2f}s with {} URL(s)".format(time.monotonic() - started, len(self.url_list)))
            return True
        else:
            logging.error("Unable to fetch RSS because there are no feeds loaded")
            return False

    def load_feeds(self, filepath: str) -> bool:
        """ Load feeds from a JSON file """
        if filepath and os.path.exists(filepath):
            f = open(filepath)
            data = json.load(f)
            if "feeds" in data:
                self.feed_list = data.get("feeds")
                logging.info("{} feeds loaded".format(len(self.feed_list)))
                return True
        else:
            logging.error("No feeds loaded")
            return False

    def get_feeds(self) -> dict:
        """ Return the list of loaded feeds"""
        return self.feed_list

    def debug_load_urls(self, urls) -> bool:
        """ Debug function to load a set of URLS"""
        self.url_list = urls

    def fetch_rawhtml(self, url) -> str:
        """Fetch URL content with browser impersonation for Cloudflare-protected pages."""
        if not url:
            return False
        try:
            response = cf_requests.get(url, impersonate="chrome124", timeout=30)
            return response.text
        except requests.exceptions.Timeout:
            logging.error("Timeout when fetching raw HTML for {}".format(url))
            return False
        except Exception as e:
            logging.error("Unable to fetch raw HTML for {} {}".format(url, e))
            return False

    def get_page_title(self, url, rawhtml=False) -> str:
        page_title = ""

        if not rawhtml:
            rawhtml = self.fetch_rawhtml(url)
            if not rawhtml:
                return page_title
        soup = BeautifulSoup(rawhtml, 'html.parser')
        for title in soup.find_all('title'):
            page_title = "{} {}".format(page_title, title.get_text())
        return page_title.strip()


class MispScraperRedis():
    def __init__(self) -> None:
        config = MispScraperConfig()
        self.config = config

        self.redis = redis.Redis(host=config.redis_host, port=config.redis_port, password=config.redis_password, decode_responses=True)
        self.misp_scraper_event = MispScraperEvent()
        self.channel = config.redis_channel
        self.scraper_redis_sleep = config.redis_scraper_redis_sleep
        self.misp_scraper_tags_prefix = config.misp_scraper_tags_prefix

    def publish(self, message) -> bool:
        """ Publish to Redis"""
        try:
            if message:
                logging.debug("Publish redis {}".format(message["link"]))
                self.redis.publish(self.channel, json.dumps(message))
        except Exception as e:
            logging.error("Unable to publish message {} {}".format(json.dumps(message), e))

    def subscribe(self) -> bool:
        """ Subscribe to the Redis messages and create MISP events for incoming messages"""
        sub = self.redis.pubsub()
        sub.subscribe(self.channel)
        logging.info("Starting subscribe")
        for message in sub.listen():

            link = ""
            if message["type"] == "message":
                data = message["data"]
                data = json.loads(data)
                link = data["link"].strip()
                feed = data["feed"]
                feed_title = data["feed_title"]
                feed_tags = data["feed_tags"]
                title = data["title"]
                rawhtml = data.get("rawhtml", False)
                additional_attributes = data.get("additional_attributes", [])

                if not link.startswith(("http://", "https://")):
                    link = "https://{}".format(link)

                try:
                    if not title:
                        f = MispScraperFeedparser()
                        if rawhtml:
                            title = f.get_page_title(False, rawhtml)
                            if not title or len(title) < 1:
                                title = "Raw HTML"
                        else:
                            title = f.get_page_title(link)

                    if link:
                        # Avoid adding the event twice
                        misp_title = "{}{}".format(self.config.misp_scraper_event, title).strip()
                        misp_tag = "{}:data-collection-source:{}".format(misp_scraper_tags_prefix, feed_title)
                        res = self.misp_scraper_event.misp.search(eventinfo=misp_title, tags=[misp_tag], pythonify=True)
                        if len(res) == 0:
                            self.misp_scraper_event.create_event(feed_title, feed, title, link, feed_tags, rawhtml, additional_attributes)
                            time.sleep(self.scraper_redis_sleep)
                        else:
                            logging.debug("Skipping creation of MISP event {}, already there.".format(misp_title))
                except Exception as e:
                    logging.error("Unable to parse link {} {}".format(link, e))


class MispScraperEvent():
    def __init__(self) -> None:
        config = MispScraperConfig()
        self.misp_key = config.misp_key
        self.misp_url = config.misp_url
        self.misp_verifycert = config.misp_verifycert
        self.misp_distribution = config.misp_distribution
        self.misp_threat_level_id = config.misp_threat_level_id
        self.misp_analysis_level = config.misp_analysis_level
        self.misp_scraper_event = config.misp_scraper_event
        self.misp_scraper_tags = config.misp_scraper_tags
        self.misp_scraper_tags_local = config.misp_scraper_tags_local
        self.misp_scraper_tags_prefix = config.misp_scraper_tags_prefix
        self.rawhtml_distribution = config.rawhtml_distribution
        self.rawhtml_sharing_group_id = config.rawhtml_sharing_group_id
        self.misp_warninglist = config.misp_warninglist
        self.misp_warninglist_required_strings = config.misp_warninglist_required_strings
        self.autodelete_when_no_required_strings = config.autodelete_when_no_required_strings
        self.misp_hard_delete_on_cleanup = config.misp_hard_delete_on_cleanup
        self.manual_feedsource = config.manual_feedsource
        self.misp_retentiontime = config.misp_retentiontime
        self.autodelete_when_assumed_errors = config.autodelete_when_assumed_errors
        self.attach_pdf = config.attach_pdf
        self.add_source_website_as_tag = add_source_website_as_tag

        self.misp_headers = {
            "Authorization": self.misp_key,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest"
        }

        self.misp = PyMISP(self.misp_url, self.misp_key, self.misp_verifycert)
        #self.misp = ExpandedPyMISP(self.misp_url, self.misp_key, self.misp_verifycert)

    def _add_attribute(self, event, category, type, comment, value, correlate=False) -> bool:
        """ Add an attribute to a MISP event """
        indicator = MISPAttribute()
        indicator.category = category
        indicator.type = type
        indicator.value = value
        indicator.comment = comment
        indicator.disable_correlation = correlate
        res = self.misp.add_attribute(event, indicator)
        if 'errors' in res:
            logging.error("Unable to add attribute {} to event {}".format(value, event.uuid))
            return False
        return True

    def _convert_raw_html(self, rawhtml) -> str:
        """ Strip non-relevant data from a raw HTML blob  """
        if rawhtml:
            soup = BeautifulSoup(rawhtml, 'html.parser')

            toRemove = ['script', 'head', 'header', 'footer', 'meta', 'link' 'nav', 'style']
            toStrip = ['a', 'img']

            for tag in soup.find_all(toRemove):
                tag.decompose()
            return markdownify(str(soup), heading_style='ATX', strip=toStrip)
        else:
            return False

    def _add_misp_report(self, event, link, extract_elements, rawhtml=False) -> bool:
        """ Add a MISP report to a MISP event """
        if not rawhtml and link:
            try:
                response = cf_requests.get(link, impersonate="chrome124")
                rawhtml = response.text
            except Exception as e:
                logging.error("Unable to pre-fetch raw HTML for {} {}".format(link, e))

        if rawhtml:
            html_report = MISPEventReport()
            html_report.name = "Report from raw HTML {}".format(link)
            html_report.content = self._convert_raw_html(rawhtml)
            report = self.misp.add_event_report(str(event.id), html_report)
            if 'EventReport' in report and 'id' in report['EventReport']:
                report_id = report['EventReport']['id']
                logging.debug("Raw HTML added as report")

                # Before we extra elements, check for required strings
                required_string_match = self._verify_required_strings(event)
                if self.autodelete_when_no_required_strings and not required_string_match:
                    self.misp.delete_event(event.id)
                    logging.debug("Delete event because no required string matches found")
                    return False                

                if extract_elements:
                    # Extract elements
                    event_url = "{}/eventReports/extractAllFromReport/{}.json".format(self.misp_url, report_id)
                    data = "data[EventReport][tag_event]=1&data[EventReport][id]={}".format(report_id)
                    res = requests.post(event_url, data=data, headers=self.misp_headers, verify=self.misp_verifycert)
                    logging.debug("Scraped and extracted {}".format(link))

                return True
            else:
                logging.error("Unable to add report to event from raw HTML")
                return False

        elif link:
            event_url = "{}/eventReports/importReportFromUrl/{}.json".format(self.misp_url, str(event.id))
            data = "data[EventReport][url]={}".format(parse.quote_plus(link))
            res = requests.post(event_url, data=data, headers=self.misp_headers, verify=self.misp_verifycert)
            # We don't get the HTTP errors when creating the report; doing some assumptions
            if "EventReport" not in res.json():
                logging.error("No content returned for {}".format(link))
                if self.autodelete_when_assumed_errors:
                    self.misp.delete_event(event.uuid)
                    logging.debug("Deleting event for {}".format(link))
                else:
                    self.misp.tag(event.uuid, "misp-scraper:HTTP=404")
            elif "403 Forbidden" in res.json()["EventReport"]["content"]:  # Happens for Red Canary
                logging.error("Got a 403 Forbidden for {}".format(link))
                if self.autodelete_when_assumed_errors:
                    self.misp.delete_event(event.uuid)
                    logging.debug("Deleting event for {}".format(link))
                else:
                    self.misp.tag(event.uuid, "misp-scraper:HTTP=403")
            else:
                report_id = int(res.json()["EventReport"]["id"])
                if report_id > 0:
                    # Before we extra elements, check for required strings
                    required_string_match = self._verify_required_strings(event)
                    if self.autodelete_when_no_required_strings and not required_string_match:
                        self.misp.delete_event(event.id)
                        logging.debug("Delete event because no required string matches found")
                        return False

                    if extract_elements:
                        # Extract elements
                        event_url = "{}/eventReports/extractAllFromReport/{}.json".format(self.misp_url, report_id)
                        data = "data[EventReport][tag_event]=1&data[EventReport][id]={}".format(report_id)
                        res = requests.post(event_url, data=data, headers=self.misp_headers, verify=self.misp_verifycert)
                        logging.debug("Scraped and extracted {}".format(link))

                    return True
            return False

    def _verify_required_strings(self, event) -> bool:
        """ Verify if there are strings (or substrings) present in the scraped site """
        if event and self.misp_warninglist_required_strings > 0:
            try:
                alert_values = self.misp.get_warninglist(self.misp_warninglist_required_strings, pythonify=True)
                first_event_report = int(self.misp.get_event_reports(event.id)[0]['EventReport']['id'])
                match = False

                if first_event_report > 0:
                    event_report_content = self.misp.get_event_report(first_event_report)['EventReport']['content']
                    if len(event_report_content) > 0:
                        for el in alert_values.WarninglistEntry:
                            value = el["value"]
                            if not value:
                                continue
                            escaped_value = re.escape(value)
                            if re.search(r"\b{}\b".format(escaped_value), event_report_content, re.I):
                                self.misp.tag(event.uuid, "scraper:matchstring={}".format(value))
                                logging.debug("Event report matches string {}".format(value))
                                match = True

                            elif re.search(r"{}".format(escaped_value), event_report_content, re.I):
                                self.misp.tag(event.uuid, "scraper:matchsubstring={}".format(value))
                                logging.debug("Event report matches substring {}".format(value))
                                match = True

                return match

            except Exception as e:
                logging.error("Failed to parse warninglist for required strings {} {}".format(self.misp_warninglist_required_strings, e))
                return False
        else:
            return False

    def cleanup_event(self, event) -> bool:
        """ Remove unwanted attributes from an event"""
        if event and self.misp_warninglist > 0:
            try:
                cleanup_values = self.misp.get_warninglist(self.misp_warninglist, pythonify=True)
                cleaned_any = False
                for el in cleanup_values.WarninglistEntry:
                    value = el["value"]
                    to_cleanup = self.misp.search('attributes', value=value, eventid=event.id)
                    if "Attribute" in to_cleanup and len(to_cleanup["Attribute"]) > 0:
                        for attribute in to_cleanup["Attribute"]:
                            attribute_id = attribute["id"]
                            self.misp.delete_attribute(attribute_id, hard=self.misp_hard_delete_on_cleanup)
                            logging.info("Clean up attribute {} - {}".format(attribute_id, value))
                            cleaned_any = True
                return cleaned_any

            except Exception as e:
                logging.error("Failed to parse warninglist for cleanup of attributes {} {}".format(self.misp_warninglist, e))
                return False
        else:
            return False

    def _extract_primary_data_source(self, link):
        parsed_url = urlparse(link)
        hostname = parsed_url.hostname
    
        try:
            ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            if ip_pattern.match(hostname):
                primary_data_source = "direct-ip"
            else:
                # Split the hostname into parts and keep the last two segments
                parts = hostname.split('.')
                if len(parts) > 2:
                    hostname = '.'.join(parts[-2:])
                primary_data_source = hostname
        except Exception as e:
            primary_data_source = False
            
        return primary_data_source
    
    def create_event(self, feed, feedsource, title, link, feed_tags, rawhtml=False, additional_attributes=[]) -> bool:
        """ Create a MISP event """
        if link:
            event = MISPEvent()
            event.distribution = self.misp_distribution
            event.threat_level_id = self.misp_threat_level_id
            event.analysis = self.misp_analysis_level
            event.info = "{}{}".format(self.misp_scraper_event, title)

            try:
                event = self.misp.add_event(event, pythonify=True)
                logging.info("Created MISP event {} for {}".format(event.uuid, title))

                for tag in self.misp_scraper_tags:
                    self.misp.tag(event.uuid, tag)

                for tag in self.misp_scraper_tags_local:
                    self.misp.tag(event.uuid, tag, local=True)
                    
                for tag in feed_tags:
                    self.misp.tag(event.uuid, tag, local=True)
                    
                data_source = "{}:data-collection-source:{}".format(misp_scraper_tags_prefix, feed)                
                self.misp.tag(event.uuid, data_source, local=True)
                
                if self.add_source_website_as_tag:
                    primary_data_source = self._extract_primary_data_source(link)
                    if primary_data_source:
                        primary_data_source_tag = "{}:primary-data-collection-source:{}".format(misp_scraper_tags_prefix, primary_data_source)
                        self.misp.tag(event.uuid, primary_data_source_tag, local=True)
                        
                if self.misp_retentiontime:
                    self.misp.tag(event.uuid, "retention:{}".format(self.misp_retentiontime), local=True)
                #self.misp.tag(event.uuid, "misp-scraper:{}".format(feed), local=True)

                self._add_attribute(event, "Other", "comment", "Blog title", title)
                if feedsource != self.manual_feedsource:
                    self._add_attribute(event, "External analysis", "link", "Feed URL", feedsource, True)
                else:
                    self._add_attribute(event, "Other", "comment", "Feed URL", feedsource)
                self._add_attribute(event, "External analysis", "link", "Blog URL", link)

                if rawhtml:
                    self._add_attribute(event, "Other", "comment", "Raw HTML", "Submit via raw HTML")

                if len(additional_attributes) > 0:
                    for attr in additional_attributes:
                        self._add_attribute(event, attr["category"], attr["type"], attr["value"], attr["comment"])
                self._add_misp_report(event, link, extract_elements, rawhtml)

                if self.attach_pdf:
                    logging.info("Attach PDF not yet implemented")
                    
                self.cleanup_event(event)

                return event
            except Exception as e:
                logging.error("Failed in trying to create a MISP event {} {}".format(title, e))
                return False
        else:
            logging.error("Failed in trying to create a MISP event without a link {}".format(title))
            return False


class MispScraperCron():
    def __init__(self) -> None:
        self.feedparser = MispScraperFeedparser()
        self.redis = MispScraperRedis()
        config = MispScraperConfig()
        self.config = config
        self.misp_retentiontime = config.misp_retentiontime

    def refresh_feed_data(self) -> None:
        """ Update the list of links found in RSS """
        logging.info("Loading feed list from {}".format(self.config.feedlist))
        self.feedparser.load_feeds(self.config.feedlist)
        self.feedparser.get_feeds()
        logging.info("Starting feed parsing")
        self.feedparser.fetch_rss()
        logging.info("Feed parsing completed")

    def push_to_redis(self) -> None:
        """ Push the links to Redis"""
        urls = self.feedparser.get_urls()
        logging.info("Publishing {} URL(s) to Redis".format(len(urls)))
        for index, el in enumerate(urls, start=1):
            if index % 25 == 0:
                logging.info("Publishing progress: {}/{}".format(index, len(urls)))
            rawhtml = self.feedparser.fetch_rawhtml(el.get("link", False))
            if rawhtml:
                el["rawhtml"] = rawhtml
            self.redis.publish(el)
        logging.info("Finished publishing to Redis")

    def cleanup_events(self) -> None:
        """ Cleanup old events (passed retention date and workflow not complete"""
        if self.misp_retentiontime:
            misp = MispScraperEvent().misp
            events = misp.search(controller="events", tags=["workflow:state=\"incomplete\""], timestamp=["3650d", "{}".format(self.misp_retentiontime)])
    
            if len(events) > 0:
                for event in events:
                    misp.delete_event(event["Event"]["id"])
                    logging.info("Delete outdated event {} - {}".format(event["Event"]["id"], event["Event"]["info"]))
            else:
                logging.debug("No outdated events found during cron")
        else:
            logging.debug("No retention time specified, not cleaning up events")


class MispScraperConfig():
    def __init__(self) -> None:

        self.misp_key = misp_key
        self.misp_url = misp_url
        self.misp_verifycert = misp_verifycert
        self.misp_distribution = misp_distribution
        self.misp_threat_level_id = misp_threat_level_id
        self.misp_analysis_level = misp_analysis_level
        self.misp_scraper_event = misp_scraper_event
        self.misp_retentiontime = misp_retentiontime
        self.misp_scraper_tags = misp_scraper_tags
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_password = redis_password
        self.redis_channel = redis_channel
        self.redis_scraper_redis_sleep = redis_scraper_redis_sleep
        self.misp_scraper_log = misp_scraper_log
        self.app_name = app_name
        self.manual_feed = manual_feed
        self.manual_feedsource = manual_feedsource
        self.flask_secret_key = flask_secret_key
        self.flask_address = flask_address
        self.flask_port = flask_port
        self.flask_certificate_file = flask_certificate_file
        self.flask_certificate_keyfile = flask_certificate_keyfile
        self.flask_url = flask_url
        self.logging_level = logging_level
        self.feedlist = feedlist
        self.rawhtml_distribution = rawhtml_distribution
        self.rawhtml_sharing_group_id = rawhtml_sharing_group_id
        self.misp_warninglist = misp_warninglist
        self.misp_warninglist_required_strings = misp_warninglist_required_strings
        self.autodelete_when_no_required_strings = autodelete_when_no_required_strings
        self.misp_hard_delete_on_cleanup = misp_hard_delete_on_cleanup
        self.autodelete_when_assumed_errors = autodelete_when_assumed_errors
        self.extract_elements = extract_elements
        self.misp_scraper_tags_local = misp_scraper_tags_local
        self.misp_scraper_tags_prefix = misp_scraper_tags_prefix
        self.attach_pdf = attach_pdf

###############################################
config = MispScraperConfig()
if config.logging_level == "debug":
    logging.basicConfig(filename=config.misp_scraper_log, level=logging.DEBUG, format="%(asctime)s - {} - %(name)-5s - %(message)s".format(config.app_name))
    logging.info("Starting with DEBUG")
else:
    logging.basicConfig(filename=config.misp_scraper_log, level=logging.INFO, format="%(asctime)s - {} - %(name)-5s - %(message)s".format(config.app_name))
    logging.info("Starting with INFO")

logging.getLogger("pymisp").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.ERROR)
urllib3.disable_warnings()

app = Flask(__name__)
app.config['SECRET_KEY'] = config.flask_secret_key


@app.route('/', methods=['POST', 'GET'])
def index():
    feed_title = config.manual_feed
    feed = config.manual_feedsource

    redis = MispScraperRedis()

    if request.method == 'POST':
        title = request.form['title']
        link = request.form['link']
        rawhtml = request.form['rawhtml']

        try:
            if not rawhtml and not link:
                flash("A link is required!", "alert")
            else:
                additional_attributes = [{'category': 'Other', 'type': 'comment', 'comment': 'Remote IP', 'value': '{}'.format(request.remote_addr)}]
                try:
                    redis.publish({
                        "link": link,
                        "title": title,
                        "feed_title": feed_title,
                        "feed": feed,
                        "rawhtml": rawhtml,
                        "feed_tags": "",
                        "additional_attributes": additional_attributes
                            })
                    flash("Manual submit to queue {} {}".format(title, link), "info")
                    logging.info("Manual submit to queue {} {}".format(title, link))
                except Exception as e:
                    flash("Failed to submit to queue {} {}".format(title, link), "alert")
                    logging.error("Failed to submit to queue {} {} {}".format(title, link, e))

            return redirect(url_for("index"))
        except Exception as e:
            flash("Error when processing POST request from {}".format(request.remote_addr), "alert")
            logging.error("Error when processing POST request from {} {}".format(request.remote_addr, e))

    return render_template('add-url.html', app_title=config.app_name, misp_url=config.misp_url, manual_feed=feed_title, manual_feedsource=feed)


if __name__ == "__main__":
    if sys.argv[1] == "cron":
        c = MispScraperCron()
        logging.info("Starting cron")
        c.cleanup_events()
        c.refresh_feed_data()
        c.push_to_redis()
        logging.info("Finished cron")
    elif sys.argv[1] == "subscribe":
        r = MispScraperRedis()
        while True:
            r.subscribe()
    elif sys.argv[1] == "flask":
        logging.info("")
        if config.flask_certificate_file and  config.flask_certificate_keyfile:
            app.run(host=config.flask_address, port=config.flask_port, debug=True, ssl_context=(config.flask_certificate_file, config.flask_certificate_keyfile))
        else:
            app.run(host=config.flask_address, port=config.flask_port, debug=True)

