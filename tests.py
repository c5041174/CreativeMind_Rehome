import unittest
from app import app, DB_PATH
from logics.logic import get_user_by_email, update_new_password


# Test cases for user-related functions
class TestUserFunctions(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_get_user_by_email(self):
        # Test fetching a user by email
        email = "tayo@yahoo.com"
        user = get_user_by_email(email, DB_PATH)
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], email)

    def test_update_user_password(self):
        # Test updating user password
        email = "tayo@yahoo.com"
        new_password = "new_secure_password"
        update_new_password(new_password, email, DB_PATH)
        user = get_user_by_email(email, DB_PATH)
        self.assertIsNotNone(user)
        self.assertEqual(user["password"], new_password)

    def tearDown(self):
        pass

    def runTest(self):
        self.test_get_user_by_email()
        self.test_update_user_password()


if __name__ == "__main__":
    unittest.main()
