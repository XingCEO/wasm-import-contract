import unittest
from wasm_import_contract import analyze

class BinaryTests(unittest.TestCase):
    def test_function_import(self):
        r=analyze({'wasm_hex':'0061736d01000000020b0103656e76036c6f670000','host':[{'module':'env','name':'log','kind':'function'}]})
        self.assertTrue(r['name_and_kind_match'])
        self.assertTrue(r['requires_type_validation'])
    def test_empty_module(self):
        self.assertEqual(analyze({'wasm_hex':'0061736d01000000'})['imports'],[])
    def test_truncated(self):
        with self.assertRaises(ValueError): analyze({'wasm_hex':'0061736d01000000020b01'})
    def test_bad_header(self):
        with self.assertRaises(ValueError): analyze({'wasm_hex':'0000000000000000'})
    def test_kind_mismatch(self):
        r=analyze({'wasm_hex':'0061736d01000000020b0103656e76036c6f670000','host':[{'module':'env','name':'log','kind':'memory'}]})
        self.assertEqual(r['findings'][0]['kind'],'import_kind_mismatch')
