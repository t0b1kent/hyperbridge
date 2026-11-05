import hashlib
import json
import re
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

    def test_wow64_source_is_replayed_after_common_tails_without_changing_fex64(self):
        pin, product, _, _, _ = producer.inputs()
        selected, selected_product = producer.source_for_variant('fex64', pin, product)
        self.assertIs(selected, pin)
        self.assertIs(selected_product, product)
        selected, selected_product = producer.source_for_variant('fex32', pin, product)
        self.assertEqual(selected['post_tail'][:-1], pin['post_tail'])
        self.assertEqual(len(pin['post_tail']), 2)
        self.assertEqual(selected['post_tail'][-1], pin['wow64_source']['post_tail'])
        self.assertEqual(selected['product_postimage_count'], 6940)
        self.assertEqual(selected_product['reference_wow64_sha256'],
                         '2a48b5cec0e48f46b5f1086cdf1d8831138cb9468438e33341acc850a737b9c7')
        for header in ['MacRunnerQpcInline.h', 'MacRunnerPause.h', 'MacRunnerXfer.h']:
            self.assertNotIn('FEXCore/include/FEXCore/Utils/' + header, selected_product['product_source_postimages'])
        self.assertEqual(len(selected_product['retained_nonbuild_submodule_metadata']), 3)

    def test_wow64_missing_pin_and_tampered_manifest_are_rejected_before_source_build(self):
        pin, product, _, _, _ = producer.inputs()
        missing = dict(pin)
        missing.pop('wow64_source')
        with self.assertRaisesRegex(ValueError, 'WOW64 source pin missing'):
            producer.source_for_variant('fex32', missing, product)
        changed = dict(pin, wow64_source=dict(pin['wow64_source'], product_manifest_sha256='0' * 64))
        with self.assertRaises(ValueError):
            producer.source_for_variant('fex32', changed, product)
        self.assertIs(producer.source_for_variant('fex64', changed, product)[0], changed)

    def test_wow64_delta_and_inventory_pins_cannot_silently_drift(self):
        pin, product, _, _, _ = producer.inputs()
        changed = dict(pin, wow64_source=dict(pin['wow64_source'], product_postimage_count=1))
        with self.assertRaisesRegex(ValueError, 'inventory count differs'):
            producer.source_for_variant('fex32', changed, product)
        changed = dict(pin, wow64_source=dict(pin['wow64_source'],
                       post_tail=dict(pin['wow64_source']['post_tail'], sha256='0' * 64)))
        with self.assertRaisesRegex(ValueError, 'delta or reference differs'):
            producer.source_for_variant('fex32', changed, product)

    def test_wow64_inventory_uses_its_manifest_without_executing_a_source_build(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'inventory'
            with mock.patch.object(producer.fex, 'cloud_only'), \
                 mock.patch.object(producer.fex, 'build', side_effect=AssertionError('unexpected compilation')):
                producer.build(out, ['fex32'], stage='inventory')
            row = json.loads((out / 'RESULT.json').read_text())['variants']['fex32']
            self.assertEqual(row['postimages'], 6940)
            self.assertEqual(row['actual_source'], 'NOT_ENABLED')
            pin = json.loads((HERE / 'recipe.lock.json').read_text())
            self.assertEqual(row['product_manifest_sha256'], pin['wow64_source']['product_manifest_sha256'])

    def test_full_source_builder_returning_none_still_records_and_archives_outputs(self):
        pin, _, _, _, _ = producer.inputs()
        for variant in ['fex32', 'fex64']:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / 'full'
                expected = pin['reference_pe_sha256'][variant]
                def source_build(target, *args, **kwargs):
                    (target / 'outputs.json').write_text(json.dumps(dict(files={},
                        ec_modules=2 if variant == 'fex64' else 0,
                        unique_ec_binaries=1 if variant == 'fex64' else 0)))
                    return None
                with mock.patch.object(producer.fex, 'cloud_only'), \
                     mock.patch.object(producer.fex, 'build', side_effect=source_build), \
                     mock.patch.object(producer.release_bytes, 'compare_outputs', return_value=dict(
                         status='REFERENCE_MATCH', expected_sha256=expected, actual_sha256=expected)), \
                     mock.patch.object(producer, 'archive', return_value={'path': 'kept-source-output.tar'}):
                    producer.build(out, [variant], stage='full')
                result = json.loads((out / 'RESULT.json').read_text())
                self.assertEqual(result['status'], 'BUILT_SOURCE_ONLY_NOT_ACCEPTED')
                self.assertEqual(result['variants'][variant]['actual_dll_sha256'], expected)
                self.assertEqual(result['archive']['path'], 'kept-source-output.tar')

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
        for item in ['fail-fast: false', 'max-parallel: 2', 'nice -n 20', 'build/repro110fex/build.py']:
            self.assertIn(item, text)
        native, wow64_inputs, wow64_full, full = [json.loads(value) for value in re.findall(r"'(\[\{[^\n']+\}\])'", text)]
        self.assertEqual(native, [dict(slot='fex64-native-stand', architecture='fex64', stage='native-stand')])
        self.assertEqual([row['stage'] for row in full], ['inventory', 'patches', 'configure', 'compile', 'native-stand', 'full'])
        self.assertEqual([row['stage'] for row in wow64_inputs], ['inventory', 'patches', 'configure'])
        self.assertTrue(all(row['architecture'] == 'fex32' for row in wow64_inputs))
        self.assertEqual(wow64_full, [dict(slot='fex32-full', architecture='fex32', stage='full')])
        self.assertIn("if: always() && inputs.only == 'all'", text)
