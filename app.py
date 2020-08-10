from flask import Flask, request
from flask_mongoengine import MongoEngine
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['MONGODB_SETTINGS'] = {
    'db': 'app',
    'host': 'localhost',
    'port': 27017
}

db = MongoEngine()
db.init_app(app)

app.config["JWT_SECRET_KEY"] = "$2y$12$BB3KdKCdIseipXVt/raTRu6gu12y/ZXS0F/ko/9MBcLFZnZR/9BwS"

jwt = JWTManager(app)

class User(db.Document):
    first_name = db.StringField(max_length=50, required=True)
    last_name = db.StringField(max_length=50, required=True)
    email = db.EmailField(max_length=150, required=True, unique=True)
    password = db.BinaryField(max_length=8, required=True)
    date_created = db.DateTimeField(default=datetime.utcnow())
    
    def __init__(self, user_data={}, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)
        if(user_data != {}):
            self.first_name = user_data['first_name']
            self.last_name = user_data['last_name']
            self.email = user_data['email']
            self.password = bcrypt.generate_password_hash(user_data['password'])
            self.date_created = datetime.utcnow()

@app.route('/')
@jwt_required
def index():
    user_indentity = get_jwt_identity()
    
    user = User.objects.get(email=user_indentity)
 
    return {                
        'name': f"{user.first_name} {user.last_name}",
        'email': user.email,
        'status': 200
    }

@app.route('/user', methods=['POST'])
def create_user():        
    new_user = User(request.form)

    try:
        new_user.save()
        
        return {'msg': 'New user successfuly created', 'status': 201}
    except:
        return {'msg': 'Error trying to create new user', 'status': 401}
    
@app.route('/login', methods=['POST'])
def login():
    email = request.form["email"]
    password = request.form["password"]
    
    user = User.objects.get(email=email)
    
    if user and bcrypt.check_password_hash(user.password, password) == True:
        access_token = create_access_token(identity=user.email)
        
        return {
            'msg': 'Login successful',
            'access_token': access_token,
            'status': 201
        }
    else:
        return {'msg': 'Invalid email and/or password', 'status': 401}

if __name__ == '__main__':
    app.run(debug=True)