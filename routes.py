from flask import render_template
from flask import Flask

app = Flask(__name__)
@app.route('/')

def home():
    user = {'username': 'Supuni'}
    posts = [
        {
            'author': {'username': 'John'},
            'body': 'Beautiful day in Portland!'
        },
        {
            'author': {'username': 'Susan'},
            'body': 'The Avengers movie was so cool!'
        }
    ]
    return render_template('index.html', title='Home', user=user, posts=posts)