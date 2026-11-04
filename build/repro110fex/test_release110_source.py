import hashlib
import json
import tempfile
from pathlib import Path
from unittest import TestCase, mock
import candidate_source as source
import build as producer

HERE = Path(__file__).resolve().parent

class ReleaseSource(TestCase):
    def test_c32_source_and_accepted_reference_are_selected(self):
        pin, product, engine, locks, tools = producer.inputs()
        self.assertEqual(pin['product_manifest'], 'c32/PRODUCT-MANIFEST.json')
        self.assertEqual(pin['product_postimage_count'], 6944)
        self.assertEqual(pin['platform']['jobs'], 2)
        self.assertEqual(pin['reference_pe_sha256']['fex64'],
                         '721cc325e3c42a06f6638b3d5f49b2261e82baa0a13d4789e9b340579048dc84')
        self.assertEqual([r['file'] for r in pin['post_tail']],
                         [product['c12_delta']['patch'], product['release110_delta']['patch']])
        self.assertEqual(product['source_verification']['base']['status'], 'PASS_EXACT_PRODUCT_SOURCE')
        self.assertEqual(product['source_verification']['changed_files'], 74)

    def test_supplement_receipt_names_its_own_bytes_after_multiple_tails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b'own supplement payload\n'
            first = root / 'first.patch'; first.write_bytes(b'first tail\n')
            last = root / 'last.patch'; last.write_bytes(b'last tail\n')
            rows = [dict(file=p.name, sha256=source.sha(p)) for p in [first, last]]
            pin = dict(candidate_revision='0' * 40, candidate_directory='own', candidate_order_file='order.json',
                       candidate_manifest_sha256='1' * 64, supplement_files=['one.cpp', 'two.cpp'],
                       supplement_source_sha256='2' * 64)
            with mock.patch.object(source, 'candidate', return_value=[]), \
                 mock.patch.object(source, 'supplement', return_value=raw), \
                 mock.patch.object(source, 'post_tail_rows', return_value=rows):
                result = source.apply(root, root, pin, {}, root, root, lambda argv, name: None)
            self.assertEqual(result['supplement_sha256'], hashlib.sha256((root / 'c9-source-tests.patch').read_bytes()).hexdigest())
            self.assertNotEqual(result['supplement_sha256'], source.sha(last))

    def test_matrix_has_independent_stage_cells_and_bounded_parallelism(self):
        text = (HERE.parents[1] / '.github/workflows/repro110-fex-c32-stages-macos15-arm64.yml').read_text()
        for item in ['fail-fast: false', 'max-parallel: 2', 'stage: inventory', 'stage: patches',
                     'stage: configure', 'stage: compile', 'stage: native-stand', 'nice -n 20', 'build/repro110fex/build.py']:
            self.assertIn(item, text)
