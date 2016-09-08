from flask import Flask, render_template,request,redirect,url_for

app = Flask(__name__)
#Index page route
@app.route("/",methods=["GET", "POST"])
def home():
    if request.method=="GET":
        return render_template("index.html")
    else:
        #Check informations about the requesting agent
        sLevel = check_user(request.form["name"], request.environ)
        #And send to the appropriate login page
        return redirect_login(sLevel)

def check_user(uName,env):
    #go trhough the registered users and check if user exists
    # check as well the ip/info about hens connection
    return 0

def redirect_login(securityLevel):
    print "Security level = ",securityLevel
    if securityLevel < 4:
        return redirect(url_for("login", sl=securityLevel))

    else:
        return redirect(url_for("denied"))


@app.route("/login")
def login():
    if int(request.args['sl']) == 0:
        params = {"pwd2":"False","sms":"False"}
    elif int(request.args['sl']) == 1 or int(request.args['sl']) == 2:
        params = {"pwd2":"True","sms":"False"}
    else:
        params = {"pwd2":"True","sms":"True"}

    return render_template("login.html", param=params)


@app.route('/denied',methods=["GET","POST"])
def denied():
    if request.method=="GET":
        return render_template("denied.html")
    else:
        return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()
