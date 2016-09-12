import unittest
import main

class MainTest(unittest.TestCase):
    def setUp(self):
        self.app = main.app.test_client()
        self.app.testing = True

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
        result = self.app.get('/login')
        self.assertEqual(result.status_code, 400)
        result = self.app.get("/login?name=azer")
        self.assertEqual(result.status_code, 400)
        result = self.app.get("/login?sl=1")
        self.assertEqual(result.status_code, 400)
        result = self.app.get("/login?name=azer&sl=1")
        self.assertEqual(result.status_code, 200)


    """ Test of the routing for the post methods
        It would be interesting to check if the page is the one expected (TOIMPROVE)"""
    def test_route_post_status_code(self):
        # sends HTTP post request to the application
        result = self.app.post('/', data=dict(name="azer"),follow_redirects=True)
        # assert the status code of the response
        self.assertEqual(result.status_code, 200)


        result = self.app.post('/login', data=dict(name="azer"), follow_redirects=True)
        self.assertFalse(result.status_code==200)
        # security lvl0 & 1
        result = self.app.post('/login?name=azer&sl=0', data=dict(name="azer",pwd="azer",sl="0"), follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        result = self.app.post('/login?name=azer&sl=0', data=dict(name="azer",pwd="wrong",sl="0"), follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        result = self.app.post('/login?name=azer&sl=0', data=dict(name="wrong",pwd="wrong",sl="0"), follow_redirects=True)
        self.assertEqual(result.status_code, 200)

        # security lvl2 & 3
        result = self.app.post('/login?name=azer&sl=2',
                               data=dict(name="azer", pwd="azer", sl="2"),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 400)
        result = self.app.post('/login?name=azer&sl=2',
                               data=dict(name="azer", pwd="azer",pwd2="azer2", sl="2"),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        result = self.app.post('/login?name=azer&sl=2',
                               data=dict(name="azer", pwd="azer",pwd2="wrong", sl="2"),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)
        result = self.app.post('/login?name=azer&sl=2',
                               data=dict(name="azer", pwd="wrong",pwd2="wrong", sl="2"),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)

        # security lvl > 4
        # go to login
        result = self.app.post('/login?name=azer&sl=4',
                               data=dict(name="azer", pwd="azer",pwd2="azer2", sl="4"),
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)


        result = self.app.post('/denied',
                               follow_redirects=True)
        self.assertEqual(result.status_code, 200)

