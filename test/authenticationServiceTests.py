import unittest
from authenticationService import AuthenticationService


class Request():
    def __init__(self,arg):
        if arg == 0:
            self.form = {'name':"azer", 'pwd':"azer"}
        elif arg == 1:
            self.form = {'name': "azer", 'pwd': "wrong"}
        else:
            self.form = {'name': "wrong", 'pwd': "wrong"}

        self.remote_addr = ['192.168.1.5']
        self.user_agent = "firefox"


class AuthServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = AuthenticationService()
        self.request0 = Request(0)
        self.request1 = Request(1)
        self.request2 = Request(2)

        self.service.users[1].IPAddressUsed.append("192.168.1.5")
        self.service.users[1].browserUsed.append("firefox")

    def test_authenticationService(self):
        self.assertEqual(self.service.failedConnection,0)
        self.assertEqual(len(self.service.users[0].connectionSuccess),0)
        self.assertEqual(len(self.service.users[0].connectionFailed),0)

        #Known user and correct credentials (user[0])
        self.service.authentication_service(self.request0)
        self.assertEqual(self.service.failedConnection, 0)
        self.assertEqual(len(self.service.users[0].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[0].connectionFailed), 0)

        #known user but wrong credentials
        self.service.authentication_service(self.request1)
        self.assertEqual(self.service.failedConnection, 1)
        self.assertEqual(len(self.service.users[0].connectionSuccess),1)
        self.assertEqual(len(self.service.users[0].connectionFailed),1)

        #Unknown user
        self.service.authentication_service(self.request2)
        self.assertEqual(self.service.failedConnection, 2)
        self.assertEqual(len(self.service.users[0].connectionSuccess),1)
        self.assertEqual(len(self.service.users[0].connectionFailed),1)

    def test_evalUserRisk(self):
        self.assertEqual(self.service.eval_user_risk("hadrien","firefox","192.168.1.5"),0)

        self.assertEqual(self.service.eval_user_risk("hadrien","firefox","192.168.1.9"),1)
        self.assertEqual(self.service.eval_user_risk("hadrien","Chrome","192.168.1.5"),1)

        self.assertEqual(self.service.eval_user_risk("hadrien","Chrome","192.168.1.9"),2)

        self.assertEqual(self.service.eval_user_risk("007","firefox","192.168.1.5"),self.service.maxSecurityLevel)
