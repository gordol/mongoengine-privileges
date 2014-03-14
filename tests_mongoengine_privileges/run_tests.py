


import unittest


if __name__ == '__main__':
    test_loader = unittest.defaultTestLoader.discover( '.' )
    test_runner = unittest.TextTestRunner()
    result = test_runner.run( test_loader )
