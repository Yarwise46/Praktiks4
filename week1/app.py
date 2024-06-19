from flask import Flask, render_template,url_for

app = Flask(__name__)


@app.route('/')
@app.route('/home')
def index():
    return render_template("index.html")


@app.route('/main')
def about():
    return render_template("title.html")


if __name__ == "__main__":
    app.run(debug=True)