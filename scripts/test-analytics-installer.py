import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('installer', Path(__file__).with_name('add-analytics.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTest(unittest.TestCase):
    def test_sitemap_template_idempotence_and_replacement(self):
        original = Path.cwd()
        args = sys.argv
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                Path('industries').mkdir()
                Path('sitemap.xml').write_text('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://voxdonna.com/</loc></url><url><loc>https://voxdonna.com/industries/test.html</loc></url></urlset>')
                for name in ['index.html', 'industries/test.html', 'blog-post.html', 'private.html']:
                    Path(name).write_text('<html><head></head><body></body></html>')
                sys.argv = ['add-analytics.py', 'G-TEST123456']
                installer.main()
                first = Path('index.html').read_text()
                installer.main()
                self.assertEqual(first, Path('index.html').read_text())
                self.assertIn('data-measurement-id', Path('industries/test.html').read_text())
                self.assertIn('data-measurement-id', Path('blog-post.html').read_text())
                self.assertNotIn('data-measurement-id', Path('private.html').read_text())
                sys.argv = ['add-analytics.py', 'G-OTHER12345']
                installer.main()
                self.assertEqual(Path('index.html').read_text().count('data-measurement-id'), 1)
                self.assertNotIn('G-TEST123456', Path('index.html').read_text())
            finally:
                os.chdir(original)
                sys.argv = args


if __name__ == '__main__':
    unittest.main()
