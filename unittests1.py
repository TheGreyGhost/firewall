import unittest
from dbaccess import DBaccess
from errorhandler import DatabaseError

class MyTestCase(unittest.TestCase):
    def test_databaseconnections(self):
        with DBaccess() as newdb:
            newdb.testconnection()

        with self.assertRaises(DatabaseError):
            with DBaccess(username="invalid", dbpassword="junk") as newdb:
                newdb.testconnection()

if __name__ == '__main__':
    unittest.main()
