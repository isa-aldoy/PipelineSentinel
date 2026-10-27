import unittest,tempfile,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from sentinel import scan
class Tests(unittest.TestCase):
 def test_unsafe(self):
  rules={f['rule'] for f in scan(pathlib.Path(__file__).resolve().parents[1]/'examples/unsafe.yml')}
  self.assertTrue({'write-all','untrusted-checkout','untrusted-expression','unpinned-action'}<=rules)
 def test_safe(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=pathlib.Path(tmp)/'ci.yml';p.write_text('on: push\npermissions: {contents: read}\njobs: {}\n')
   self.assertEqual(scan(p),[])
