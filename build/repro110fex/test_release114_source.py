"""Offline c34r source delta controls; fixtures are never compiled."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import release114_source as step


class SourceProfiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('REPRO109_TEST_TMP'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.here = self.root / 'recipe'; self.here.mkdir()
        self.tree = self.root / 'source'; self.tree.mkdir()
        self.before = {'own.cpp': b'// c33r\n', 'keep.h': b'// keep\n'}
        self.after = {'own.cpp': b'// c34r\n', 'keep.h': b'// keep\n', 'new.h': b'// new\n'}
        digest = lambda data: hashlib.sha256(data).hexdigest()
        for name, data in self.before.items():
            (self.tree / name).write_bytes(data)
        base = dict(product_source_postimages={n: digest(d) for n, d in self.before.items()})
        base_path = self.here / 'base.json'; base_path.write_text(json.dumps(base))
        changes = []
        for name in ('new.h', 'own.cpp'):
            store = 'postimage-' + name
            (self.here / store).write_bytes(self.after[name])
            changes.append(dict(path=name, before_sha256=digest(self.before[name]) if name in self.before else None,
                                after_sha256=digest(self.after[name]), store=store, bytes=len(self.after[name])))
        product = dict(schema=1, variant='fex32', base_product_manifest='base.json',
                       base_product_manifest_sha256=digest(base_path.read_bytes()), changes=changes,
                       product_source_postimages={n: digest(d) for n, d in self.after.items()})
        path = self.here / 'profile.json'; path.write_text(json.dumps(product))
        self.config = dict(schema=1, profiles=dict(fex32=dict(path='profile.json',
                           sha256=digest(path.read_bytes()), files=3, changes=2)))

    def test_exact_preimage_is_transformed_and_verified(self):
        report = step.apply(self.config, 'fex32', self.tree, self.here)
        self.assertEqual(report['status'], 'C34R_EXACT_SOURCE_PROFILE_APPLIED')
        self.assertEqual({p.name: p.read_bytes() for p in self.tree.iterdir()}, self.after)
        with self.assertRaisesRegex(ValueError, 'Product postimages differ'):
            step.apply(self.config, 'fex32', self.tree, self.here)

    def test_wrong_base_refuses_before_creating_any_new_source(self):
        (self.tree / 'own.cpp').write_bytes(b'// different base\n')
        with self.assertRaisesRegex(ValueError, 'Product postimages differ'):
            step.apply(self.config, 'fex32', self.tree, self.here)
        self.assertFalse((self.tree / 'new.h').exists())

    def test_changed_postimage_refuses_before_changing_source(self):
        (self.here / 'postimage-own.cpp').write_bytes(b'// corruption\n')
        with self.assertRaisesRegex(ValueError, 'postimage content differs'):
            step.apply(self.config, 'fex32', self.tree, self.here)
        self.assertEqual({p.name: p.read_bytes() for p in self.tree.iterdir()}, self.before)

    def test_only_the_32_bit_profile_exists(self):
        with self.assertRaisesRegex(ValueError, 'Unknown c34r source profile'):
            step.profile(self.config, 'fex64', self.here)

    def test_published_profile_is_pinned_and_chains_from_c33r(self):
        pin = json.loads((Path(step.__file__).parent / 'recipe.lock.json').read_bytes())
        config = step.read_config(pin)
        product = step.profile(config, 'fex32')
        self.assertEqual(len(product['changes']), 25)
        self.assertEqual(product['base_product_manifest'], 'c33r/fex32.json')
        self.assertEqual(product['pe_link_timestamp'], 1788779471)
        self.assertEqual(len(product['reference_pe_sha256']), 64)


if __name__ == '__main__':
    unittest.main()
