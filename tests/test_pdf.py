""" Articles that are a PDF get a report with the text of the PDF. Run with: python -m unittest discover tests """
import types
import unittest
import zlib

from curl_cffi.requests import Headers, Response

from test_dedup import FEED_URL, DedupTestCase, ms

ARTICLE = "https://www.ic3.gov/CSA/2026/261105.pdf"


def make_pdf(*pages) -> bytes:
    """ A PDF with one page for each text; an empty text gives a page without text, as in a scanned PDF """
    count = len(pages)
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(b"%d 0 R" % (4 + 2 * i) for i in range(count)), count),
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    for i, text in enumerate(pages):
        # Compressed, as in most PDFs, so the text is not in the file as it is
        stream = zlib.compress("BT /F1 12 Tf 72 720 Td ({}) Tj ET".format(text).encode() if text else b"")
        objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 3 0 R >> >> >>" % (5 + 2 * i))
        objects.append(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream")

    pdf = b"%PDF-1.4\n"
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += b"%d 0 obj\n" % number + obj + b"\nendobj\n"
    xref = len(pdf)
    pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    pdf += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return pdf


def fetched(content, content_type="application/pdf") -> Response:
    """ An article as curl_cffi returns it """
    response = Response()
    response.status_code = 200
    response.content = content
    response.headers = Headers({"Content-Type": content_type} if content_type else {})
    return response


class TestIsPdf(unittest.TestCase):
    def test_content_type(self) -> None:
        self.assertTrue(ms.is_pdf(fetched(b"", "application/pdf")))
        self.assertTrue(ms.is_pdf(fetched(b"", "Application/PDF; qs=0.001")))

    def test_pdf_sent_as_other_type(self) -> None:
        self.assertTrue(ms.is_pdf(fetched(make_pdf("x"), "application/octet-stream")))
        self.assertTrue(ms.is_pdf(fetched(b"\r\n" + make_pdf("x"), None)))

    def test_html(self) -> None:
        self.assertFalse(ms.is_pdf(fetched(b"<html><p>%PDF-1.7 files with JavaScript</p></html>", "text/html")))
        self.assertFalse(ms.is_pdf(fetched(b"", None)))


class PdfTestCase(DedupTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.event = ms.MISPEvent()
        self.event.id = 727
        self.event.uuid = "uuid-727"
        self.fake.misp.add_event.return_value = self.event
        self.fake.misp.add_attribute.return_value = {}
        self.fake.misp.add_event_report.return_value = {"EventReport": {"id": 1}}
        self.creator = ms.MispScraperEvent()

    def report(self) -> ms.MISPEventReport:
        self.fake.misp.add_event_report.assert_called_once()
        return self.fake.misp.add_event_report.call_args.args[1]


class TestConvertPdf(PdfTestCase):
    def test_text(self) -> None:
        self.assertEqual(self.creator._convert_pdf(make_pdf("Akira ransomware"), ARTICLE), "Akira ransomware")

    def test_pages(self) -> None:
        self.assertEqual(self.creator._convert_pdf(make_pdf("Akira", "", "TTPs"), ARTICLE), "Akira\n\nTTPs")

    def test_no_text(self) -> None:
        self.assertEqual(self.creator._convert_pdf(make_pdf(""), ARTICLE), "")

    def test_not_readable(self) -> None:
        for pdf in [b"", b"%PDF-1.4\nnot a PDF after all", make_pdf("Akira")[:100]]:
            with self.subTest(pdf=pdf), self.assertLogs(level="ERROR"):
                self.assertEqual(self.creator._convert_pdf(pdf, ARTICLE), "")


class TestPdfReport(PdfTestCase):
    def test_report_has_text_of_pdf(self) -> None:
        self.cf_get.return_value = fetched(make_pdf("Akira ransomware"))

        self.assertTrue(self.creator._add_misp_report(self.event, ARTICLE, False))

        self.assertEqual(self.report().name, "Report from PDF {}".format(ARTICLE))
        self.assertEqual(self.report().content, "Akira ransomware")
        self.requests_post.assert_not_called()

    def test_pdf_without_text(self) -> None:
        for pdf in [make_pdf(""), b""]:
            with self.subTest(pdf=pdf):
                self.fake.misp.reset_mock()
                self.cf_get.return_value = fetched(pdf)

                self.assertFalse(self.creator._add_misp_report(self.event, ARTICLE, False))

                self.fake.misp.add_event_report.assert_not_called()
                self.fake.misp.delete_event.assert_not_called()
                self.requests_post.assert_not_called()
                self.fake.misp.tag.assert_called_once_with("uuid-727", "misp-scraper:PDF=no-text", local=False)

    def test_html_still_converted(self) -> None:
        self.cf_get.return_value = fetched(b"<html><head><title>t</title></head><p>Akira</p></html>", "text/html")

        self.assertTrue(self.creator._add_misp_report(self.event, ARTICLE, False))

        self.assertEqual(self.report().name, "Report from raw HTML {}".format(ARTICLE))
        self.assertEqual(self.report().content.strip(), "Akira")

    def test_pdf_not_passed_as_raw_html(self) -> None:
        self.cf_get.return_value = fetched(make_pdf("Akira ransomware"))

        self.assertFalse(ms.MispScraperFeedparser().fetch_rawhtml(ARTICLE))

    def test_event_for_pdf_article(self) -> None:
        self.cf_get.return_value = fetched(make_pdf("Akira ransomware"))

        self.creator.create_event("IC3", FEED_URL, "Akira", ARTICLE, [])

        self.assertEqual(self.report().content, "Akira ransomware")
        comments = [a.args[1].comment for a in self.fake.misp.add_attribute.call_args_list]
        self.assertNotIn("Raw HTML", comments)


class TestPdfRequiredStrings(PdfTestCase):
    """ The required strings and the extraction run on the text of the PDF """
    def setUp(self) -> None:
        super().setUp()
        self.creator.misp_warninglist_required_strings = 5
        self.creator.autodelete_when_no_required_strings = True
        self.fake.misp.get_warninglist.return_value = types.SimpleNamespace(WarninglistEntry=[{"value": "Akira"}])
        self.fake.misp.get_event_reports.return_value = [{"EventReport": {"id": 1}}]
        self.fake.misp.get_event_report.side_effect = lambda report_id: {"EventReport": {"content": self.report().content}}

    def test_match(self) -> None:
        self.cf_get.return_value = fetched(make_pdf("Akira ransomware"))

        self.assertTrue(self.creator._add_misp_report(self.event, ARTICLE, True))

        self.fake.misp.tag.assert_called_once_with("uuid-727", "scraper:matchstring=Akira", local=False)
        self.fake.misp.delete_event.assert_not_called()
        self.assertEqual(self.requests_post.call_args.args[0], "https://misp.example/eventReports/extractAllFromReport/1.json")

    def test_no_match(self) -> None:
        self.cf_get.return_value = fetched(make_pdf("Play ransomware"))

        self.assertFalse(self.creator._add_misp_report(self.event, ARTICLE, True))

        self.fake.misp.delete_event.assert_called_once_with(727)
        self.requests_post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
