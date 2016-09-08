from user import User

class AuthenticationService:
    def __init__(self):
        self.maxSecurityLevel = 4
        self.failedConnection = 0
        self.users = [User("azer", "azer","azer2"), User("hadrien", "h","h2")]

