import unittest

from kite.admin.permission import Permission

class TestPermission(unittest.TestCase):
    def test_parse(self):
        with self.assertRaises(TypeError):
            Permission('://')

        with self.assertRaises(TypeError) as cm:
            Permission('http://google.com')
        self.assertIn('kite+perm', cm.exception.args[0])

        with self.assertRaises(ValueError):
            Permission('kite+perm://flywithkite.com/admin/')

        with self.assertRaises(ValueError):
            Permission('kite+perm://flywithkite.com/admin///')

        with self.assertRaises(ValueError):
            Permission('kite+perm://flywithkite.com/admin')

        with self.assertRaises(ValueError):
            Permission('kite+perm://flywithkite.com//')

        with self.assertRaises(ValueError):
            Permission('kite+perm://flywithkite.com///')

        p = Permission('kite+perm://flywithkite.com/admin/permission')
        self.assertEqual(p.app_domain, 'flywithkite.com')
        self.assertEqual(p.app_name, 'admin')
        self.assertEqual(p.permission, 'permission')

        p = Permission('kite+perm://flywithkite.com/admin/nested/permission')
        self.assertEqual(p.app_domain, 'flywithkite.com')
        self.assertEqual(p.app_name, 'admin')
        self.assertEqual(p.permission, 'nested/permission')

        self.assertEqual(p.application, 'kite+app://flywithkite.com/admin')
