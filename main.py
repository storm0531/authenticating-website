from flask import Flask, render_template, redirect, request, url_for, flash, send_from_directory
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.secret_key = "xxxxxxxx"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column('user_id', db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)


with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        hashed_and_salted_password = generate_password_hash(request.form["password"], salt_length=8)
        new_user = User(name=request.form["name"],
                        email=request.form["email"],
                        password=hashed_and_salted_password)
        if User.query.filter_by(email=new_user.email).first():
            flash("you are already have registered with this email please login")
            return redirect(url_for("login"))
        else:
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("home"))
    return render_template("register.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user:
            if check_password_hash(pwhash=user.password,
                                   password=request.form.get("password")):
                login_user(user)
                return redirect(url_for("home"))
            else:
                flash("password incorrect try again")
                return render_template("login.html")
        else:
            flash("this email not registered please register your email")
            return redirect(url_for("register"))
    return render_template("login.html")


@login_required
@app.route("/result")
def result():
    return render_template("result.html")


@login_required
@app.route("/downlaod")
def download():
    return send_from_directory('static', path='images/Sky.jpg')


@login_required
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
