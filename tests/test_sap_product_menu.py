import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "chrome", Path(__file__).resolve().parents[1] / "scripts/build-chrome.py")
chrome = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chrome)


class ProductMenuTests(unittest.TestCase):
    def test_desktop_mobile_and_footer_scope(self):
        anchor = '<a href="sap-analytics.html">SAP AI Copilot</a>'
        footer = '<footer>' + anchor + '</footer>'
        body = '<main>' + anchor + '</main>'
        html = ('<nav><div class="nav-drop-panel">' + anchor + '</div></nav>'
                '<div class="mobile-menu" id="mobileMenu">' + anchor + '</div>'
                + body + footer)
        result = chrome.add_sap_deduplication(html)
        self.assertEqual(result.count('href="/demo/sap-deduplication/"'), 2)
        self.assertIn(body + footer, result)
        self.assertEqual(chrome.add_sap_deduplication(result), result)

    def test_shared_generated_navigation(self):
        nav = chrome.nav_html()
        self.assertIn('href="/demo/sap-deduplication/"', nav)
        self.assertEqual(chrome.add_sap_deduplication(nav), nav)

    def test_no_anchor_is_unchanged(self):
        html = '<nav><a href="/about.html">About</a></nav>'
        self.assertEqual(chrome.add_sap_deduplication(html), html)

    def test_existing_label_in_content_does_not_hide_missing_menu(self):
        html = ('<nav><a href="/sap-analytics.html">SAP AI Copilot</a></nav>'
                '<main><a href="/demo/sap-deduplication/">Demo</a></main>')
        self.assertEqual(chrome.add_sap_deduplication(html).count(
            'href="/demo/sap-deduplication/"'), 2)


if __name__ == '__main__':
    unittest.main()
