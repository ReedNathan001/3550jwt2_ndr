import datetime
import socket
import threading
import time
import unittest
from http.server import HTTPServer
from unittest.mock import patch

import jwt
import requests
from jwt3550NDR import jwt_server


class TestMyServer(unittest.TestCase):
    SERVER_ADDRESS = ("localhost", 8080)

    def test_invalid_jwt_token(self):
        headers = {'Authorization': 'Bearer invalid_token'}
        response = requests.get("http://localhost:8080/auth", headers=headers)
        self.assertEqual(response.status_code, 405)

    def test_missing_jwt_token(self):
        response = requests.get("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 405)

    def test_server_response_time(self):
        start_time = time.time()
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        end_time = time.time()
        response_time = end_time - start_time
        self.assertLess(response_time, 1)  # Fail if response time is more than 1 second

    @classmethod
    def setUpClass(cls):
        if cls._is_server_running():
            print("Server is already running")
        else:
            cls._start_server()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'server'):
            cls._shutdown_server()

    @staticmethod
    def _is_server_running():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            return sock.connect_ex(TestMyServer.SERVER_ADDRESS) == 0

    @classmethod
    def _start_server(cls):
        cls.server = HTTPServer(TestMyServer.SERVER_ADDRESS, jwt_server)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def _shutdown_server(cls):
        cls.server.shutdown()
        cls.server.server_close()
        time.sleep(1)  # Wait for the server to shutdown

    @staticmethod
    def validate_rsa_public_key(key):
        return (
            key.get('kty') == 'RSA' and
            'n' in key and
            'e' in key
        )        

    def test_auth_methods(self): #verify RESTful auth endpoint
        self._test_methods("/auth", ["GET", "PUT", "DELETE", "PATCH", "HEAD"])

    def test_jwks_methods(self): #verify RESTful jwks endpoint
        self._test_methods("/.well-known/jwks.json", ["POST", "PUT", "DELETE", "PATCH"]) 

    def _test_methods(self, endpoint, methods):
        for method in methods:
            response = requests.request(method, f"http://localhost:8080{endpoint}")
            self.assertEqual(response.status_code, 405, f"Expected 405 for {method} {endpoint}, got {response.status_code}")

    def test_jwks_rsa_key(self):
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertIn("keys", jwks)
        keys = jwks["keys"]
        self.assertEqual(len(keys), 1)
        key = keys[0]
        self.assertEqual(key["kty"], "RSA")
        self.assertTrue(self.validate_rsa_public_key(key))

    def test_get_well_known_jwks(self): #verify kid
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertIn("keys", jwks)
        keys = jwks["keys"]
        self.assertEqual(len(keys), 1)
        key = keys[0]
        self.assertEqual(key["alg"], "RS256")
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["kid"], "goodKID")

    @patch('jwt3550NDR.datetime')
    def test_generate_jwt_token(self, mock_datetime): 
        #check if /auth endpoint returns unexpired, signed jwt on post request                                            
        mock_datetime.utcnow.return_value = datetime.datetime(2023, 10, 26)
        self._verify_jwt_token()

        #check if /auth endpoint returns expired, signed jwt on post request with expired query
        mock_datetime.utcnow.return_value = datetime.datetime(2023, 10, 25)
        self._verify_jwt_token("?expired=true")
#NATHAN DIWA REED ndr0057
    def _verify_jwt_token(self, query=""):
        response = requests.post(f"http://localhost:8080/auth{query}")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token)
        headers = jwt.get_unverified_header(token)

        # Check if the "kid" in the JWT header is "expiredKID" when the "expired" parameter is true
        if "expired=true" in query:
            self.assertEqual(headers["kid"], "expiredKID")

        payload = jwt.decode(token, algorithms=["RS256"], options={"verify_signature": False})
        self.assertEqual(payload["user"], "username")


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestMyServer)
    runner = unittest.TextTestRunner()
    result = runner.run(suite)

    total = result.testsRun
    failed = len(result.failures)
    errored = len(result.errors)
    passed = total - failed - errored

    print(f"\nPassed: {passed}/{total} ({(passed/total)*100:.2f}%)")