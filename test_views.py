import unittest
from flask import Flask
from flask_testing import TestCase
from app import app
import os

class MyTest(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF protection for testing

        return app

    def test_index_returns_200_status_code(self):
        response = self.client.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_contact_form_returns_200_status_code(self):
        response = self.client.get('/contact', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_contact_form_submission(self):
        with self.client:
            response = self.client.post('/contact', follow_redirects=True, data={
                'first_name': 'John',
                'last_name': 'Doe',
                'email': 'johndoe@example.com',
                'phone': '1234567890',
                'message': 'Hello, this is a test message',
                'g-recaptcha-response': 'dummy-recaptcha-response'
            })
            self.assertEqual(response.status_code, 200)

    def test_registration_personal_form_returns_200_status_code(self):
        response = self.client.get('/registration-personal', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_registration_location_form_returns_200_status_code(self):
        response = self.client.get('/registration-location', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_registration_business_form_returns_200_status_code(self):
        response = self.client.get('/registration-business', follow_redirects=True)
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
