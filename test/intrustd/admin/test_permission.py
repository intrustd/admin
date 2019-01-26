import unittest

from intrustd.admin.permission import Permission

class TestPermission(unittest.TestCase):
    def test_parse(self):
        with self.assertRaises(TypeError):
            Permission('://')

        with self.assertRaises(TypeError) as cm:
            Permission('http://google.com')
        self.assertIn('intrustd+perm', cm.exception.args[0])

        with self.assertRaises(ValueError):
            Permission('intrustd+perm://admin.intrustd.com/')

        with self.assertRaises(ValueError):
            Permission('intrustd+perm://admin.intrustd.com///')

        with self.assertRaises(ValueError):
            Permission('intrustd+perm://admin.intrustd.com')

        with self.assertRaises(ValueError):
            Permission('intrustd+perm://intrustd.com//')

        with self.assertRaises(ValueError):
            Permission('intrustd+perm://intrustd.com///')

        p = Permission('intrustd+perm://admin.intrustd.com/permission')
        self.assertEqual(p.app, 'admin.intrustd.com')
        self.assertEqual(p.permission, 'permission')

        p = Permission('intrustd+perm://admin.intrustd.com/nested/permission')
        self.assertEqual(p.app, 'admin.intrustd.com')
        self.assertEqual(p.permission, 'nested/permission')
