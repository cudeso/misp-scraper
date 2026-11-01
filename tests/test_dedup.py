""" One article gives one MISP event, whichever feeds bring it in. Run with: python -m unittest discover tests """
import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
TAGS_LOCAL = ["zsazsa:source=\"misp-scraper\"", "workflow:state=\"incomplete\""]


def load_scraper():
    """ Load misp-scraper.py with the default configuration; nothing connects to MISP or redis """
    config = types.ModuleType("scraper")
    exec(compile((ROOT / "scraper.py.default").read_text(), "scraper.py.default", "exec"), config.__dict__)
    config.misp_scraper_log = os.devnull
    config.misp_url = "https://misp.example"
    config.misp_scraper_tags_local = TAGS_LOCAL
    sys.modules["scraper"] = config

    spec = importlib.util.spec_from_file_location("misp_scraper", ROOT / "misp-scraper.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ms = load_scraper()

ARTICLE = "https://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html"
FEED_URL = "http://thehackernews.com/feeds/posts/default"


class FakeMisp():
    """ Keeps the link attributes of the events, and answers the attribute search like MISP """
    def __init__(self) -> None:
        self.attributes = []
        self.manual_events = []
        self.search_response = None
        self.misp = mock.MagicMock()
        self.misp.search.side_effect = self.search

    def add_event(self, uuid, blog_url, feed_url=FEED_URL, tags=TAGS_LOCAL) -> None:
        for comment, value in [("Feed URL", feed_url), ("Blog URL", blog_url)]:
            self.attributes.append({"type": "link", "category": "External analysis", "comment": comment,
                                    "value": value, "Event": {"uuid": uuid}, "tags": tags})

    def add_manual_event(self, info) -> None:
        self.manual_events.append(info)

    def search(self, controller="events", eventinfo=None, value=None, type_attribute=None, category=None, tags=None, **kwargs):
        if self.search_response is not None:
            return self.search_response
        if controller == "events":
            return [info for info in self.manual_events if info == eventinfo and tags == ["scraper:data-collection-source:Manual"]]
        matches = [a for a in self.attributes if a["value"] in value and a["type"] == type_attribute
                   and a["category"] == category and set(a["tags"]) & set(tags)]
        return {"Attribute": matches}


class DedupTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = FakeMisp()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(ms, "PyMISP", return_value=self.fake.misp).start()
        # Fetching an article goes through one of these
        self.cf_get = mock.patch.object(ms.cf_requests, "get").start()
        self.requests_post = mock.patch.object(ms.requests, "post").start()

        with mock.patch.object(ms.redis, "Redis"):
            self.subscriber = ms.MispScraperRedis()
        self.subscriber.scraper_redis_sleep = 0
        self.create_event = mock.patch.object(self.subscriber.misp_scraper_event, "create_event").start()

    def receive(self, *messages) -> None:
        """ Deliver messages to the subscriber as they come from the redis channel """
        pubsub = self.subscriber.redis.pubsub.return_value
        pubsub.listen.return_value = [{"type": "subscribe", "data": 1}] + [{"type": "message", "data": json.dumps(m)} for m in messages]
        self.subscriber.subscribe()

    def message(self, link, feed_title="IT-ISAC Open Source News", feed="https://it-isac.example/feed", title="") -> dict:
        return {"link": link, "feed_title": feed_title, "feed": feed, "title": title, "feed_tags": [], "published": "2026-10-27"}

    def manual_message(self, link, title="", rawhtml="<html><title>Dahua</title><p>Dahua cameras</p></html>") -> dict:
        """ As the Flask form publishes it """
        return {"link": link, "feed_title": "Manual", "feed": "Manual", "title": title, "rawhtml": rawhtml, "feed_tags": ""}


class TestNormaliseUrl(unittest.TestCase):
    def test_variants_of_the_same_article(self) -> None:
        for variant in [
            "http://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html",
            "https://THEHACKERNEWS.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html",
            "https://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html/",
            "https://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html#comments",
            "https://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html?utm_source=feedburner&utm_medium=feed",
            "https://thehackernews.com/2026/10/attackers-hijack-dahua-ip-cameras-in.html?fbclid=IwAR0abc",
        ]:
            with self.subTest(variant=variant):
                self.assertEqual(ms.normalise_url(variant), ARTICLE)

    def test_keeps_parameters_that_identify_the_article(self) -> None:
        self.assertEqual(ms.normalise_url("http://example.com/news.php?id=42&utm_campaign=x&lang=en#top"),
                         "https://example.com/news.php?id=42&lang=en")
        self.assertNotEqual(ms.normalise_url("https://example.com/news.php?id=42"),
                            ms.normalise_url("https://example.com/news.php?id=43"))

    def test_different_articles_stay_different(self) -> None:
        self.assertNotEqual(ms.normalise_url(ARTICLE), ms.normalise_url(ARTICLE.replace("dahua", "hikvision")))
        self.assertNotEqual(ms.normalise_url("https://example.com/a"), ms.normalise_url("https://example.org/a"))
        self.assertNotEqual(ms.normalise_url("https://example.com/a"), ms.normalise_url("https://example.com:8443/a"))

    def test_leaves_what_is_not_a_web_url(self) -> None:
        self.assertEqual(ms.normalise_url("https://"), "https://")
        self.assertEqual(ms.normalise_url("Manual"), "Manual")


class TestSubscriber(DedupTestCase):
    def test_same_article_from_second_feed(self) -> None:
        self.fake.add_event("uuid-727", ARTICLE)

        with self.assertLogs(level="INFO") as logs:
            self.receive(self.message(ARTICLE))

        self.create_event.assert_not_called()
        self.cf_get.assert_not_called()
        self.requests_post.assert_not_called()
        # Only the feed tag; the workflow, admiralty-scale and product tags and the reports stay as they are
        self.fake.misp.tag.assert_called_once_with("uuid-727", "scraper:data-collection-source:IT-ISAC Open Source News", local=True)
        self.fake.misp.untag.assert_not_called()
        self.fake.misp.add_event_report.assert_not_called()
        self.fake.misp.add_attribute.assert_not_called()
        self.fake.misp.delete_event.assert_not_called()
        self.assertTrue(any("INFO" in line and "IT-ISAC Open Source News" in line and ARTICLE in line and "uuid-727" in line
                            for line in logs.output))

    def test_explicit_lookup(self) -> None:
        self.receive(self.message(ARTICLE + "?utm_source=rss"))

        self.fake.misp.search.assert_called_once()
        kwargs = self.fake.misp.search.call_args.kwargs
        self.assertEqual(kwargs["controller"], "attributes")
        self.assertEqual(kwargs["type_attribute"], "link")
        self.assertEqual(kwargs["tags"], TAGS_LOCAL)
        self.assertEqual(kwargs["value"], [ARTICLE, ARTICLE + "?utm_source=rss"])
        self.assertNotIn("eventinfo", kwargs)

    def test_variants_from_second_feed(self) -> None:
        for variant in [ARTICLE.replace("https://", "http://"), ARTICLE + "/", ARTICLE + "?utm_source=feedburner&utm_medium=feed"]:
            with self.subTest(variant=variant):
                self.fake.attributes = []
                self.fake.misp.tag.reset_mock()
                self.fake.add_event("uuid-727", ARTICLE)

                self.receive(self.message(variant))

                self.create_event.assert_not_called()
                self.fake.misp.tag.assert_called_once_with("uuid-727", "scraper:data-collection-source:IT-ISAC Open Source News", local=True)

    def test_event_from_before_normalisation(self) -> None:
        # Stored as it came in, with the tracking parameter
        self.fake.add_event("uuid-old", ARTICLE + "?utm_source=feedburner")

        self.receive(self.message(ARTICLE + "?utm_source=feedburner"))

        self.create_event.assert_not_called()

    def test_different_article(self) -> None:
        self.fake.add_event("uuid-727", ARTICLE)
        other = ARTICLE.replace("dahua", "hikvision")

        self.receive(self.message(other, title="Hikvision"))

        self.create_event.assert_called_once()
        self.assertEqual(self.create_event.call_args.args[3], other)
        self.fake.misp.tag.assert_not_called()

    def test_feed_url_is_not_the_article(self) -> None:
        # An event whose feed URL is this link, but whose article is another one
        self.fake.add_event("uuid-feed", ARTICLE.replace("dahua", "other"), feed_url=ARTICLE)

        self.receive(self.message(ARTICLE, title="Dahua"))

        self.create_event.assert_called_once()

    def test_not_an_event_of_the_scraper(self) -> None:
        self.fake.add_event("uuid-other", ARTICLE, tags=["tlp:clear"])

        self.receive(self.message(ARTICLE, title="Dahua"))

        self.create_event.assert_called_once()

    def test_failed_lookup(self) -> None:
        self.fake.search_response = {"errors": (500, {"message": "Internal error"})}

        with self.assertLogs(level="WARNING") as logs:
            self.receive(self.message(ARTICLE, title="Dahua"))

        self.create_event.assert_called_once()
        self.fake.misp.tag.assert_not_called()
        self.assertTrue(any("WARNING" in line and ARTICLE in line for line in logs.output))

    def test_lookup_raises(self) -> None:
        self.fake.misp.search.side_effect = ConnectionError("MISP is down")

        with self.assertLogs(level="WARNING"):
            self.receive(self.message(ARTICLE, title="Dahua"))

        self.create_event.assert_called_once()

    def test_same_article_from_two_feeds_at_once(self) -> None:
        # The second message is only read once the event for the first one is there
        self.create_event.side_effect = lambda feed, feedsource, title, link, *args: self.fake.add_event("uuid-new", ms.normalise_url(link))

        self.receive(self.message(ARTICLE, feed_title="HackerNews", feed=FEED_URL, title="Dahua"),
                     self.message(ARTICLE.replace("https://", "http://"), title="Dahua"))

        self.create_event.assert_called_once()
        self.fake.misp.tag.assert_called_once_with("uuid-new", "scraper:data-collection-source:IT-ISAC Open Source News", local=True)


class TestManualSubmit(DedupTestCase):
    def test_content_for_collected_article(self) -> None:
        self.fake.add_event("uuid-727", ARTICLE)

        self.receive(self.manual_message(ARTICLE, title="Dahua"))

        self.create_event.assert_called_once()
        self.fake.misp.tag.assert_not_called()

    def test_raw_html_submitted_twice(self) -> None:
        self.fake.add_manual_event("Scraper: Dahua")

        self.receive(self.manual_message(""))

        self.create_event.assert_not_called()
        self.assertEqual(self.fake.misp.search.call_args.kwargs["eventinfo"], "Scraper: Dahua")

    def test_link_submitted_twice(self) -> None:
        self.fake.add_manual_event("Scraper: Dahua")

        self.receive(self.manual_message(ARTICLE, title="Dahua"))

        self.create_event.assert_not_called()

    def test_new_raw_html(self) -> None:
        self.fake.add_manual_event("Scraper: Hikvision")

        self.receive(self.manual_message(""))

        self.create_event.assert_called_once()

    def test_failed_lookup(self) -> None:
        self.fake.search_response = {"errors": (500, {"message": "Internal error"})}

        with self.assertLogs(level="WARNING"):
            self.receive(self.manual_message(""))

        self.create_event.assert_called_once()


class TestCreateEvent(DedupTestCase):
    def test_stores_normalised_article_url(self) -> None:
        event = ms.MISPEvent()
        event.id = 727
        event.uuid = "uuid-727"
        self.fake.misp.add_event.return_value = event
        self.fake.misp.add_attribute.return_value = {}
        self.fake.misp.add_event_report.return_value = {"EventReport": {"id": 1}}
        creator = ms.MispScraperEvent()

        creator.create_event("HackerNews", FEED_URL, "Dahua", ARTICLE + "?utm_source=feedburner#x", [], "<html><p>Dahua</p></html>")

        stored = {(a.args[1].comment, a.args[1].value) for a in self.fake.misp.add_attribute.call_args_list}
        self.assertIn(("Blog URL", ARTICLE), stored)
        self.assertIn(("Feed URL", FEED_URL), stored)
        self.assertEqual(self.fake.misp.add_event_report.call_args.args[1].name, "Report from raw HTML {}".format(ARTICLE))
        self.fake.misp.tag.assert_any_call("uuid-727", "scraper:data-collection-source:HackerNews", local=True)


if __name__ == "__main__":
    unittest.main()
