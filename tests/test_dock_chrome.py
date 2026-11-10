import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "chrome", Path(__file__).resolve().parents[1] / "scripts/build-chrome.py")
chrome = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chrome)


class DockTagTests(unittest.TestCase):
    def test_added_once_before_last_body_end_and_idempotent(self):
        html = '<body><script>var s="</body>"</script><p>x</p></body></html>'
        once = chrome.add_dock(html)
        self.assertEqual(once.count("vd-chrome:dock -->"), 2)  # open and close markers
        self.assertTrue(once.index("dock.js") > once.index("<p>x</p>"))
        self.assertEqual(chrome.add_dock(once), once)

    def test_refreshes_a_stale_tag(self):
        stale = chrome.DOCK_BLOCK.replace(chrome.DOCK_VERSION, "00000000")
        self.assertEqual(chrome.add_dock("<body>" + stale + "</body>"), "<body>" + chrome.DOCK_BLOCK + "</body>")

    def test_homepage_is_skipped_and_blog_posts_are_covered(self):
        targets = chrome.dock_targets()
        self.assertNotIn("index.html", targets)
        self.assertIn("demos.html", targets)
        self.assertTrue(any(t.startswith("blog/en/") for t in targets))


if __name__ == "__main__":
    unittest.main()
