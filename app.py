from crypt import methods
from enum import unique
from re import L
from turtle import color
from flask import Flask, redirect, url_for, render_template, request, session, jsonify, after_this_request
from flask import Flask, render_template, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.sql import func
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ARRAY


#finance imports
import yfinance as yf
import plotly.graph_objects as go
import pandas as pd


#os/system imports
import datetime
import sys
import os


'''
IMPORTANT IDEAS AND CHECKLIST TYPE THING.
-   
'''



app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

secret_key = os.urandom(32)
app.config['SECRET_KEY'] = secret_key

#Users database model.
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    date_created = db.Column(DateTime, default=(datetime.datetime.utcnow ))
    last_active = db.Column(db.String, nullable=True)
    #Need to add a isAdmin Boolean to check if admin is on/off for users.

    

class Articles(db.Model):
    __tablename__ = 'articles'
    id = db.Column(db.Integer, primary_key=True)
    
    title = db.Column(db.String, nullable=False)
    article = db.Column(db.Text, nullable=False)

    author = db.Column(db.Integer, nullable=False)

    
db.create_all()

#Function checking when user is last active.
def lastActive():
    current_time = f'{datetime.datetime.utcnow():%Y-%m-%d %H:%M:%S%z}'
    query = Users.query.filter_by(username=session['username']).first()
    query.last_active = current_time
    db.session.commit()

#Home route. Checking if user is signed in already or not, then routing to the index html page.
@app.route("/")
def home():
    users = Users.query.all()
    if 'username' in session:
        username = session['username']
        
        if 'admin' in session:
            return render_template("index.html", users=users, username=username, admin=session['admin'])
        
        return render_template("index.html", users=users, username=username)
    return render_template("index.html", users=users)


@app.route("/login", methods=['POST', 'GET'])
def login():
    
    #If the request is a post, it comes from login page, we handle the request here.
    if 'username' not in session:
        if request.method == 'POST':
            
            username = request.form.get("username")
            
            #Encryption on password:
            password = request.form.get("password")
            
            #Creating a query, using username as a key.
            query = Users.query.filter_by(username=username).first()
            
            # "if query" checks to see if there is a username in the database.
            if query:
                #if the username query equals the username we took from the form (same with password), user is logged in.
                if query.username == username and bcrypt.check_password_hash(query.password, password):
                    session['username'] = username
                    lastActive()
                    if query.username == 'admin':
                        
                        #storing admin variable in the session
                        session['admin'] = True
                        #Tell terminal/CMD that Admin has logged in (security).
                        print('ADMIN HAS LOGGED IN. ADMIN HAS LOGGED IN.', file=sys.stdout)
                        users = Users.query.all()
                        
                        return render_template('index.html', username=session['username'], admin = session['admin'], users=users)
                    return render_template('index.html', username=session['username'])
            
            login_error = True
            return render_template("login.html", login_error=login_error)
    #Finally, if the request is not a post OR if the login details are incorrect, we redirect to the login page.
        return render_template("login.html")
    return redirect(url_for('home'))

@app.route("/register", methods=['POST', 'GET'])
def register():
    #if user is signed in, we redirect user to the home page.
    if 'username' in session:
        return redirect(url_for("home"))
    
    #If the request is a post (from form), then the email, username and password is taken from the form.
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        #Password is encrypted for security reasons.
        password = bcrypt.generate_password_hash(request.form.get("password")).decode("utf-8")

        if email and username and password:
            new_User = Users(email = email, username=username, password=password)
            db.session.add(new_User)
            db.session.commit()
            return redirect(url_for('home'))
        else:
            return '/404'
    else: 
        return render_template("register.html")
    return render_template("register.html")

@app.route('/about')
def about():
    #Redirecting user if they ARE signed in.
    if 'username' in session:
        return render_template("about.html", username = session['username'])
    
    return render_template("about.html")

@app.route('/contact')
def contact():
    if 'username' in session:
        if 'admin' in session:
            return render_template("contact.html", username=session['username'], admin=session['admin'])
        return render_template("contact.html", username = session['username'])
    else:
        return render_template("contact.html")

@app.route('/profile')
def profile():
    if 'username' in session:
        query = Users.query.filter_by(username=session['username']).first()
        return render_template('profile.html', username=session['username'], user = query)
    

#change username
@app.route('/changeusername', methods=['POST'])
def changeUsername():
    
    if request.method == 'GET':
        return redirect(url_for("profile"))
    
    if 'username' in session:
        username1 = request.form.get('current_user1')
        username2 = request.form.get('current_user2')
        new_username = request.form.get('new_username')
        query = Users.query.filter_by(username=session['username']).first()
        
        if query.username == username1 and query.username == username2:
            if new_username != query.username and new_username:
                query.username = new_username
                db.session.commit()
                success = True
                
                if 'admin' in session:
                    session.pop('admin', None)
                if 'username' in session:
                    session.pop('username', None)
                   
                return render_template("index.html", change_name_success=success)
    change_name_fail = True
    return render_template('index.html', change_name_fail =change_name_fail )
    
#Change password
''' IGNORE FOR NOW IGNORRE FOR NOW
@app.route('/changepassword')        
def changePassword():
    
    if request.method == 'GET':
        return redirect(url_for("profile"))
    
    if 'username' in session:
        password1 = request.form.get('current_password1')
        password2 = request.form.get('current_password2')
        new_password = request.form.get('new_password')
        query = Users.query.filter_by(username=session['username']).first()
        
        if bcrypt.check_password_hash(query.password, password1) and bcrypt.check_password_hash(query.password, password2):
            password = bcrypt.generate_password_hash(new_password).decode("utf-8")
            query.password = password
            db.session.commit()
            password_changed = True
            return render_template("index.html", password_changed=password_changed)
        
    password_change_fail = True
    return render_template('index.html', password_change_fail =password_change_fail )
'''
#admin dashboard
@app.route('/admin')
def admin():
    if 'username' in session:
        #checking if the username is admin.
        if 'admin' in session:
            users = Users.query.all()
            return render_template('admin.html', username = session['username'], users=users, admin=session['admin'])
        else:
            return render_template('index.html', username = session['username'])
    else:
        return render_template('index.html')



@app.route('/stockapi', methods=['POST', 'GET'])
def stockApi():
    if 'username' in session:
        if request.method == 'POST':
            ticker = request.form.get('stock')
            return redirect(url_for("stocks", ticker = ticker))
    else:
        return render_template('index.html')



@app.route('/stocks')
def stockspage():
    return render_template("finance.html", username=session['username'])

@app.route('/stocks/<ticker>')
def stocks(ticker):
    if 'username' in session:
        #Turn this into an API that sends stock info to JS. In JS we create the graph and keep it there.
        from pandas_datareader import data as pdr
        import yfinance as yf
        import covid_daily


        yf.pdr_override()

        data = pdr.get_data_yahoo(ticker)
        datalen = len(str(data))
        
        if datalen>100:
            df = pd.DataFrame(data)
            df['MA5'] = df.Close.rolling(5).mean()
            df['MA20'] = df.Close.rolling(20).mean()
            covidData = covid_daily.data(country='us',chart='graph-deaths-daily', as_json=False)
            covid_data = go.Line(x=covidData.index, y=covidData['Novel Coronavirus Daily Deaths'], mode='lines', name='Covid deaths.')
            #covid_data2 = go.Line(x=covidCases.index, y=covidCases['Novel Coronavirus Daily Cases'],mode='lines')
            ma = go.Scatter(x=df.index, y=df.MA20, line=dict(width=1), name='20 day moving average.')
            ma5 = go.Scatter(x=df.index, y=df.MA5, line=dict(width=1), name='5 day moving average.')
            stock_data = go.Line(x=data.index, y=data['Close'],mode='lines', name=ticker+(' share price.'))
            fig = go.Figure(data=[stock_data, ma, ma5 ,covid_data, ])
            fig.update_layout(title_text=str("Graph for: '"+str(ticker)+"'"), title_x=0.5, template='seaborn')        
            fig.update_layout(
                margin=go.layout.Margin(
                    l=0,
                    r=0,
                    b=0,
                )
            )
            fig.update_layout(
                xaxis=dict(
                    rangeselector=dict(
                        buttons=list([
                            dict(count=7,
                                label='1w',
                                step='day',
                                stepmode="backward"), 
                            dict(count=1,
                                label="1m",
                                step="month",
                                stepmode="backward"),
                            dict(count=6,
                                label="6m",
                                step="month",
                                stepmode="backward"),
                            dict(count=1,
                                label="YTD",
                                step="year",
                                stepmode="todate"),
                            dict(count=1,
                                label="1y",
                                step="year",
                                stepmode="backward"),
                            dict(step="all")
                        ])
                    ),
                    rangeslider=dict(
                        visible=True
                    ),
                    type="date"
                )
            )
            lastActive()
            return render_template('finance.html',fig=fig.to_html(full_html=False),username=session['username'] )
        else:
            return redirect(url_for('stockspage'))

@app.route('/news')
def news():
    if 'username' in session:
        stock = yf.Ticker('goog')
        news = [i for i in stock.news]
        return render_template("news.html", news = news)
    else:
        return redirect(url_for('home'))
    
    
@app.route('/articles')
def articles():
    
    if 'username' in session:
        articles = Articles.query.all()
        return render_template('articles.html', articles=articles, username=session['username'])
    
@app.route('/postArticle', methods=['POST'])
def postArticle():
    if 'username' in session:
        username = session['username']
        title = request.form.get('title')
        article = request.form.get('article')
        if title and article:
            newPost = Articles(title=title, author=username, article=article)
            db.session.add(newPost)
            db.session.commit()
            posted = True
            return redirect(url_for("articles", posted=posted))
    
    return redirect(url_for("home"))

@app.route('/users/<user>')
def users(user):
    
    if 'username' in session:
        query = Articles.query.filter_by(author=str(user)).all()
        
        
        '''
            FIGURE THIS SHIT OUT CAI
            
        '''

        return render_template('user.html', articles=query, target_user = user, username=session['username'])
        
    '''allArticles = Articles.query.all()
    for article in allArticles:
        if article.author == user:
            this.append(article)'''
        


#logout feature.
@app.route('/logout')
def logout():
    if 'admin' in session:
        session.pop('admin', None)
    if 'username' in session:
        lastActive()
        session.pop('username', None)
        
    return render_template('index.html')

#error handling :)
@app.errorhandler(404)
@app.errorhandler(500)
def page_not_found(e):
    error = True
    if 'username' in session:
        return render_template('index.html', error=error, username=session['username'], e=e)
    
    return render_template('index.html', error=error, e=e)

    




#PUT USER SOMEWHERE ON PAGE.