from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    date_created = db.Column(db.DateTime)
    date_last_updated = db.Column(db.DateTime)


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    accepted = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)
    question_id = db.Column(db.Integer)
    date_created = db.Column(db.DateTime)
    date_last_updated = db.Column(db.DateTime)


class VoteQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer)
    vote_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    date_created = db.Column(db.DateTime)
    date_last_updated = db.Column(db.DateTime)


class VoteAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    answer_id = db.Column(db.Integer)
    vote_id = db.Column(db.Integer)
    date_created = db.Column(db.DateTime)
    date_last_updated = db.Column(db.DateTime)


class Vote(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        vote = db.Boolean()
        user_id = db.Column(db.Integer)
        date_created = db.Column(db.DateTime)
        date_last_updated = db.Column(db.DateTime)
