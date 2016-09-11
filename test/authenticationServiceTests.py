import unittest
from authenticationService import AuthenticationService

"""Class used to represent a fake request"""
class Request():
    def __init__(self,sl,name,p1,p2):
        self.form={'sl':sl,'name':name,'pwd':p1,'pwd2':p2}
        self.remote_addr = ['192.168.1.5']
        self.user_agent = "firefox"


class AuthServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = AuthenticationService()
        self.service.users[1].IPAddressUsed.append("192.168.1.5")
        self.service.users[1].browserUsed.append("firefox")

    """Test of the auth service method
        Using different security levels 0-1, 2-3, >3"""
    def test_authenticationService(self):
        #0-1
        sl = 0
        self.assertEqual(self.service.failedConnection,0)
        self.assertEqual(len(self.service.users[0].connectionSuccess),0)
        self.assertEqual(len(self.service.users[0].connectionFailed),0)
        #Known user and correct credentials (user[0])
        self.service.authentication_service(Request(sl,'azer','azer',"azer2"))
        self.assertEqual(self.service.failedConnection, 0)
        self.assertEqual(len(self.service.users[0].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[0].connectionFailed), 0)
        #known user but wrong credentials
        self.service.authentication_service(Request(sl,'azer','wrong','wrong'))
        self.assertEqual(self.service.failedConnection, 1)
        self.assertEqual(len(self.service.users[0].connectionSuccess),1)
        self.assertEqual(len(self.service.users[0].connectionFailed),1)
        #Unknown user
        self.service.authentication_service(Request(sl,'unknown','xxx','xxx'))
        self.assertEqual(self.service.failedConnection, 2)
        self.assertEqual(len(self.service.users[0].connectionSuccess),1)
        self.assertEqual(len(self.service.users[0].connectionFailed),1)

        #2-3
        sl=2
        self.assertEqual(self.service.failedConnection, 2)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 0)
        self.assertEqual(len(self.service.users[1].connectionFailed), 0)
        # Known user and correct credentials (user[0])
        self.service.authentication_service(Request(sl, 'hadrien', 'h', "h2"))
        self.assertEqual(self.service.failedConnection, 2)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[1].connectionFailed), 0)
        # known user but wrong credentials
        self.service.authentication_service(Request(sl, 'hadrien', 'wrong', "h2"))
        self.assertEqual(self.service.failedConnection, 3)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[1].connectionFailed), 1)
        self.service.authentication_service(Request(sl, 'hadrien', 'h', "wrong"))
        self.assertEqual(self.service.failedConnection, 4)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[1].connectionFailed), 2)
        self.service.authentication_service(Request(sl, 'hadrien', 'wrong', "wrong"))
        self.assertEqual(self.service.failedConnection, 5)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[1].connectionFailed), 3)
        # Unknown user
        self.service.authentication_service(Request(sl, '007', 'h', "h2"))
        self.assertEqual(self.service.failedConnection, 6)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[1].connectionFailed), 3)

        #>3
        sl=4
        self.assertEqual(self.service.failedConnection, 6)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[1].connectionFailed), 3)
        self.service.authentication_service(Request(sl, 'hadrien', 'h', "h2"))
        self.assertEqual(self.service.failedConnection, 7)
        self.assertEqual(len(self.service.users[1].connectionSuccess), 1)
        self.assertEqual(len(self.service.users[1].connectionFailed), 3)
        self.assertFalse(self.service.authentication_service(Request(sl, 'hadrien', 'h', "h2")))

    """Test the risk evaluation service"""
    def test_evalUserRisk(self):
        self.assertEqual(self.service.eval_user_risk("hadrien","firefox","192.168.1.5"),0)

        self.assertEqual(self.service.eval_user_risk("hadrien","firefox","192.168.1.9"),1)
        self.assertEqual(self.service.eval_user_risk("hadrien","Chrome","192.168.1.5"),1)

        self.assertEqual(self.service.eval_user_risk("hadrien","Chrome","192.168.1.9"),2)

        self.assertEqual(self.service.eval_user_risk("007","firefox","192.168.1.5"),self.service.maxSecurityLevel)
