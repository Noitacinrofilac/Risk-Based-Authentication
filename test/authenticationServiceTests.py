import unittest
from authenticationService import AuthenticationService

"""Class used to represent a fake request"""
class Request():
    def __init__(self,name,p1,p2):
        self.form={'name':name,'pwd':p1,'pwd2':p2}
        self.remote_addr = '192.168.1.5'
        self.user_agent = 'firefox'

    def tostring(self):
        return self.form," addr ",self.remote_addr," user = ",self.user_agent


class AuthServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = AuthenticationService()
        self.service.users_dict["hadrien"].IPAddressUsed.append("192.168.1.5")
        self.service.users_dict["hadrien"].browserUsed.append("firefox")

    """Test of the auth service method
        Using different security levels 0-1, 2-3, >3"""
    def test_authenticationService(self):
        #Security level 0
        self.service.eval_user_risk('azer',"firefox","192.168.1.5")
        self.service.authentication_service(Request('azer','azer','azer2'))
        self.service.eval_user_risk('azer',"firefox","192.168.1.5")
        self.assertEqual(self.service.users_security_level['azer'],0)
        self.assertEqual(self.service.failedConnection,0)
        self.assertEqual(len(self.service.users_dict['azer'].connectionSuccess),1)
        self.assertEqual(len(self.service.users_dict['azer'].connectionFailed),0)
        #Known user and correct credentials (user[0])
        self.service.authentication_service(Request('azer','azer',"azer2"))
        self.assertEqual(self.service.failedConnection, 0)
        self.assertEqual(len(self.service.users_dict['azer'].connectionSuccess), 2)
        self.assertEqual(len(self.service.users_dict['azer'].connectionFailed), 0)
        #known user but wrong credentials
        self.service.authentication_service(Request('azer','wrong','wrong'))
        self.assertEqual(self.service.failedConnection, 1)
        self.assertEqual(len(self.service.users_dict['azer'].connectionSuccess),2)
        self.assertEqual(len(self.service.users_dict['azer'].connectionFailed),1)
        #Unknown user
        self.service.authentication_service(Request('unknown','xxx','xxx'))
        self.assertEqual(self.service.failedConnection, 2)
        self.assertEqual(len(self.service.users_dict['azer'].connectionSuccess),2)
        self.assertEqual(len(self.service.users_dict['azer'].connectionFailed),1)

        #Security level 2
        self.service.eval_user_risk('hadrien',"Chrome","192.168.1.9")
        self.assertEqual(self.service.users_security_level['hadrien'],2)
        self.assertEqual(self.service.failedConnection, 2)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionSuccess), 0)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionFailed), 0)
        # Known user and correct credentials (user[0])
        self.service.authentication_service(Request( 'hadrien', 'h', "h2"))
        self.assertEqual(self.service.failedConnection, 2)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionSuccess), 1)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionFailed), 0)
        # known user but wrong credentials
        self.service.authentication_service(Request( 'hadrien', 'wrong', "h2"))
        self.assertEqual(self.service.failedConnection, 3)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionSuccess), 1)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionFailed), 1)
        self.service.authentication_service(Request('hadrien', 'h', "wrong"))
        self.assertEqual(self.service.failedConnection, 4)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionSuccess), 1)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionFailed), 2)
        self.service.authentication_service(Request( 'hadrien', 'wrong', "wrong"))
        self.assertEqual(self.service.failedConnection, 5)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionSuccess), 1)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionFailed), 3)
        # Unknown user
        self.service.authentication_service(Request('007', 'h', "h2"))
        self.assertEqual(self.service.failedConnection, 6)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionSuccess), 1)
        self.assertEqual(len(self.service.users_dict['hadrien'].connectionFailed), 3)


        #Security level max
        self.assertEqual(self.service.failedConnection, 6)
        self.service.authentication_service(Request('WRONG', 'xxx', "xxx"))
        self.assertEqual(self.service.failedConnection, 7)
        self.assertFalse(self.service.authentication_service(Request('WRONG', 'XXX', "xxx")))
        self.assertEqual(self.service.failedConnection, 8)

    """Test the risk evaluation service"""
    def test_evalUserRisk(self):
        self.assertEqual(self.service.eval_user_risk("hadrien","firefox","192.168.1.5"),0)

        self.assertEqual(self.service.eval_user_risk("hadrien","firefox","192.168.1.9"),1)
        self.assertEqual(self.service.eval_user_risk("hadrien","Chrome","192.168.1.5"),1)

        self.assertEqual(self.service.eval_user_risk("hadrien","Chrome","192.168.1.9"),2)

        self.assertEqual(self.service.eval_user_risk("007","firefox","192.168.1.5"),self.service.maxSecurityLevel)
