"""Offline c33r source application controls; fixtures are never compiled."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import release111_source as step


class SourceProfiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('REPRO109_TEST_TMP'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.here = self.root / 'recipe'; self.here.mkdir()
        self.tree = self.root / 'source'; self.tree.mkdir()
        self.before = {'own.cpp': b'// before\n', 'obsolete.h': b'// obsolete\n'}
        self.after = {'own.cpp': b'// after\n', 'new.h': b'// new\n'}
        digest = lambda data: hashlib.sha256(data).hexdigest()
        self.digest = digest
        for name, data in self.before.items():
            (self.tree / name).write_bytes(data)
        base = dict(product_source_postimages={n: digest(d) for n, d in self.before.items()})
        base_path = self.here / 'base.json'
        base_path.write_text(json.dumps(base))
        changes = []
        for name in sorted(set(self.before) | set(self.after)):
            row = dict(path=name, before_sha256=digest(self.before[name]) if name in self.before else None,
                       after_sha256=digest(self.after[name]) if name in self.after else None)
            if name in self.after:
                store = 'postimage-' + name
                (self.here / store).write_bytes(self.after[name])
                row.update(store=store, bytes=len(self.after[name]))
            changes.append(row)
        product = dict(schema=1, variant='fex32', base_product_manifest='base.json',
            base_product_manifest_sha256=digest(base_path.read_bytes()), changes=changes,
            product_source_postimages={n: digest(d) for n, d in self.after.items()})
        product_path = self.here / 'profile.json'; product_path.write_text(json.dumps(product))
        self.config = dict(profiles=dict(fex32=dict(path='profile.json', sha256=digest(product_path.read_bytes()),
                                                   files=2, changes=3)))

    def test_exact_preimage_is_transformed_and_verified(self):
        report = step.apply(self.config, 'fex32', self.tree, self.here)
        self.assertEqual(report['status'], 'C33R_EXACT_SOURCE_PROFILE_APPLIED')
        self.assertEqual({p.name: p.read_bytes() for p in self.tree.iterdir()}, self.after)
        with self.assertRaisesRegex(ValueError, 'Product postimages differ'):
            step.apply(self.config, 'fex32', self.tree, self.here)

    def test_wrong_base_refuses_before_creating_any_new_source(self):
        (self.tree / 'own.cpp').write_bytes(b'// different base\n')
        with self.assertRaisesRegex(ValueError, 'Product postimages differ'):
            step.apply(self.config, 'fex32', self.tree, self.here)
        self.assertFalse((self.tree / 'new.h').exists())
        self.assertEqual((self.tree / 'obsolete.h').read_bytes(), self.before['obsolete.h'])

    def test_changed_postimage_refuses_before_changing_source(self):
        (self.here / 'postimage-own.cpp').write_bytes(b'// corruption\n')
        with self.assertRaisesRegex(ValueError, 'postimage content differs'):
            step.apply(self.config, 'fex32', self.tree, self.here)
        self.assertEqual({p.name: p.read_bytes() for p in self.tree.iterdir()}, self.before)

    def test_unexpected_backups_and_symlinks_are_refused(self):
        extra = self.tree / 'own.cpp.orig'; extra.write_bytes(b'// own backup\n')
        with self.assertRaisesRegex(ValueError, 'Product postimages differ'):
            step.apply(self.config, 'fex32', self.tree, self.here)
        extra.unlink(); extra.symlink_to('/etc/hosts')
        with self.assertRaisesRegex(ValueError, 'Foreign source file'):
            step.apply(self.config, 'fex32', self.tree, self.here)
        self.assertFalse((self.tree / 'new.h').exists())

    def test_unknown_architecture_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'Unknown c33r source profile'):
            step.profile(self.config, 'fex128', self.here)


if __name__ == '__main__':
    unittest.main()
