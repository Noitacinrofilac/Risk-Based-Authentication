import unittest
import main
from authenticationService import AuthenticationService
from authenticationServiceTests import Request


class MainTest(unittest.TestCase):
    def setUp(self):
        self.app = main.app.test_client()
        self.app.testing = True
        self.service = AuthenticationService()

    def tearDown(self):
        self.app.delete()

    """Testing the routing with GET method"""
    def test_route_get_status_code(self):
        # sends HTTP GET request to the application
        result = self.app.get('/')
        # assert the status code of the response
        self.assertEqual(result.status_code, 200)
        result = self.app.get('/denied')
        self.assertEqual(result.status_code, 200)
        result = self.app.get('/logs')
        self.assertEqual(result.status_code, 200)
        result = self.app.get('/logs?name=test')
        self.assertEqual(result.status_code, 200)

        #Login needs an id and a security level
        result = self.app.get("/login?name=azer")
        self.assertEqual(result.status_code, 200)
        result = self.app.get('/login')
        self.assertEqual(result.status_code, 400)
        result = self.app.get("/login?sl=1")
        self.assertEqual(result.status_code, 400)


    """ Test of the routing for the post methods"""
    def test_route_post_status_code(self):
        # sends HTTP post request to the application
        result = self.app.post('/', data=dict(name="azer"),follow_redirects=True)
        # assert the status code of the response
        self.assertEqual(result.status_code, 200)


        result = self.app.post('/login', data=dict(name="azer"), follow_redirects=True)
        self.assertFalse(result.status_code==200)

        # security lvl = max security level

        self.assertEqual(self.service.users_security_level["azer"],self.service.maxSecurityLevel)
        result = self.app.post('/login?name=azer',
                               data=dict(name="azer", pwd="azer",pwd2="azer2"),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)

        # security lvl 2
        self.service.eval_user_risk("azer","firefox","192.168.1.5")
        self.assertEqual(self.service.users_security_level["azer"],2)
        result = self.app.post('/login?name=azer',
                               data=dict(name="azer",pwd="azer",pwd2='azer2'),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        result = self.app.post('/login?name=azer',
                               data=dict(name="azer",pwd="wrong",pwd2='azer2'),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        result = self.app.post('/login?name=azer',
                               data=dict(name="wrong",pwd="wrong",pwd2='azer2'),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)

        result = self.app.post('/denied',
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)

