from flask import Flask, render_template,request,redirect,url_for
from authenticationService import AuthenticationService
from datetime import datetime
"""Definition of the global variables"""
app = Flask(__name__)
service = AuthenticationService()

"""Home page
    The user write its name to access the login page that will be defined for every user"""
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method=="GET":
        print "[",datetime.now(),"][",request.method,"][",request.path,"] - User on /"
        return render_template("index.html")
    else:
        securityLevel = service.eval_user_risk(request.form['name'],request.user_agent,request.remote_addr)
        if securityLevel < service.maxSecurityLevel:
            # TODO
            # sent in GET => easily avoided => need POST
            print "[",datetime.now(),"][",request.method,"][",request.path,"] - User redirected to /login with security level ",securityLevel
            return redirect(url_for("login", sl=securityLevel, name=request.form["name"]))
        else:
            print "[",datetime.now(),"][",request.method,"][",request.path,"] - Unknown user tried to access /login. Redirected to /denied"
            return redirect(url_for("denied"))

"""Login page
    The user enter its credential according to the security level"""
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        print "[", datetime.now(), "][", request.method, "][", request.path, "] - User on /login with security level = ",request.args['sl']
        if int(request.args['sl']) == 0:
            params = {"name":request.args['name'],"pwd2":"False","sms":"False","securityLevel":request.args['sl']}
        elif int(request.args['sl']) == 1 or int(request.args['sl']) == 2:
            params = {"name":request.args['name'], "pwd2":"True","sms":"False", "securityLevel":request.args['sl']}
        else:
            params = {"name":request.args['name'], "pwd2":"True","sms":"True", "securityLevel":request.args['sl']}
        return render_template("login.html", param=params)

    elif request.method == "POST":
        if service.authentication_service(request):
            print "[",datetime.now(),"][",request.method,"][",request.path,"] - User logged in successfully and redirected to /logs"
            return redirect(url_for("checkLogs"))
        else:
            print "[",datetime.now(),"][",request.method,"][",request.path,"] - User failed to log in. Redirected to /denied"
            return redirect(url_for("denied"))
    else:
        print "[",datetime.now(),"][",request.method,"][",request.path,"] - User tried to force system (method != GET or POST in /login). Redirected to /denied "
        return redirect(url_for("denied"))

"""The user can check the information about an user using GET request"""
@app.route('/logs', methods=["GET", "POST"])
def checkLogs():
    info = []
    print "[", datetime.now(), "][", request.method, "][", request.path, "] - User on /logs"
    if request.args:
        # retrieve the information asked
        if request.args["name"]:
            info.append(request.args["name"])
            if request.args['name'] in service.users_dict:
                u = service.users_dict[request.args['name']]
                info.append(u.IPAddressUsed)
                info.append(u.browserUsed)
            """
            for u in service.users:
                if u.name == request.args['name']:
                    info.append(u.browserUsed)
                    info.append(u.IPAddressUsed)"""
        print "[",datetime.now(),"][",request.method,"][",request.path,"] - User asks for information about ", request.args['name']
    return render_template("logs.html", failed=service.failedConnection, data=info)

"""Denied route
    If a step in the login is wrong the user is redirected here"""
@app.route('/denied', methods=["GET", "POST"])
def denied():
    if request.method=="GET":
        print "[",datetime.now(),"][",request.method,"][",request.path,"] - User on /denied"
        return render_template("denied.html")
    else:
        print "[",datetime.now(),"][",request.method,"][",request.path,"] - User leaving /denied to /home"
        return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host='0.0.0.0')
