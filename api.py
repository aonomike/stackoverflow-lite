from flask import Flask, request, jsonify, make_response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from project.models import User, Question, Answer, VoteQuestion, VoteAnswer, Vote, db

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
# sqlite_uri='sqlite:////Users/globalprograms/Work/Training/Python/flask/todo/todo.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_uri
POSTGRES = {
    'user': 'globalprograms',
    'pw': 'postgres',
    'db': 'todo',
    'host': 'localhost',
    'port': '5432',
}
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
%(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
app.config['DEBUG'] = True
db.init_app(app)


def token_required(funct):
    @wraps(funct)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'token is invalid'})
        return funct(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'cannot perform that function'})
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify(output)


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'cannot perform that function'})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify(user_data)


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'cannot perform that function'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})

    user.admin = True
    db.session.commit()
    return jsonify({"message": "User is now staff!"})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"message": "No user found!"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted!"})


@app.route('/question', methods=['GET'])
@token_required
def get_all_questions(current_user):
    todos = Todo.query.all()

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        todo_data['user_id'] = todo.user_id
        output.append(todo_data)
    return jsonify(output)


@app.route('/question/<question_id>', methods=['GET'])
@token_required
def get_one_question(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({"message": "No todo found!"})
    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete
    todo_data['user_id'] = todo.user_id
    return jsonify(todo_data)


@app.route('/question', methods=['POST'])
@token_required
def create_question(current_user):
    data = request.get_json()
    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message': 'New todo created'})


@app.route('/question/<question_id>/vote', methods=['PUT'])
@token_required
def vote_question(current_user, question_id):
    question = Question.query.filter_by(id=question_id, user_id=current_user.id).first()

    if not question:
        return jsonify({'message': 'Question'})
    VoteQuestion
    question.complete = True
    db.session.commit()
    return jsonify({"message": "Successfully voted for question!"})


@app.route('/question/<question_id>', methods=['DELETE'])
@token_required
def delete_question(current_user, question_id):
    question = Question.query.filter_by(id=question_id, user_id=current_user.id)

    if not question:
        return jsonify({'message': 'missing question'})
    db.session.delete(question)
    db.session.commit()
    return jsonify({'message': 'question Successfully deleted'})


@app.route('/question/<question_id>/answer', methods=['GET'])
@token_required
def get_all_answers(current_user, question_id):

    answers = Answer.query.filter_by(question_id=question_id)

    if not answers:
        return {'message': "no answers exist for question"}

        output = []

    for answer in answers:
        answer_data = {}
        answer_data['id'] = answer.id
        answer_data['text'] = answer.text
        answer_data['accepted'] = answer.accepted
        answer_data['user_id'] = answer.user_id
        answer_data['question_id'] = answer.question_id
        answer_data['date_created'] = answer.date_created
        answer_data['date_last_updated'] = answer.date_last_updated
        output.append(answer_data)

    return jsonify(output)


@app.route('/question/<question_id>/answer/<answer_id>', methods=['GET'])
@token_required
def get_one_answer_by_question(current_user, answer_id):
    todo = Answer.query.filter_by(id=answer_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({"message": "No todo found!"})
    answer_data = {}
    answer_data['id'] = answer.id
    answer_data['text'] = answer.text
    answer_data['accepted'] = answer.accepted
    answer_data['user_id'] = answer.user_id
    answer_data['question_id'] = answer.question_id
    answer_data['date_created'] = answer.date_created
    answer_data['date_last_updated'] = answer.date_last_updated
    return jsonify(answer_data)


@app.route('/question/<question_id>/answer', methods=['POST'])
@token_required
def create_answer(current_user):
    data = request.get_json()
    answer = Answer(text=data['text'], accepted=False, user_id=current_user.id, question_id=question_id, date_created=datetime.datetime.now(), date_last_updated=datetime.datetime.now())
    db.session.add(answer)
    db.session.commit()
    return jsonify({'message': 'New Answer created'})


@app.route('/question/<question_id>/vote', methods=['PUT'])
@token_required
def vote_answer(current_user, question_id):
    question = Question.query.filter_by(id=question_id, user_id=current_user.id).first()

    if not question:
        return jsonify({'message': 'Question'})
    VoteQuestion
    question.complete = True
    db.session.commit()
    return jsonify({"message": "Successfully voted for question!"})


@app.route('/question/<question_id>/answer/<answer_id>', methods=['DELETE'])
@token_required
def delete_question(current_user, answer_id, question_id):
    answer = Answer.query.filter_by(id=answer_id, question_id=question_id, user_id=current_user.id)

    if not answer:
        return jsonify({'message': 'missing answer'})
    db.session.delete(answer)
    db.session.commit()
    return jsonify({'message': 'question Successfully deleted'})

    
@app.route('/login')
def login():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})
    return make_response('could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


if __name__ == '__main__':
    app.run(debug=True)
