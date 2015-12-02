from flask import Flask, redirect, url_for, render_template
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user,\
    current_user
from oauth import OAuthSignIn
from collections import OrderedDict


app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://postgres:postgres@localhost/ooiuiprod'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_RECORD_QUERIES'] = True
app.config['OAUTH_CREDENTIALS'] = {
    'facebook': {
        'id': '470154729788964',
        'secret': '010cc08bd4f51e34f3f3e684fbdea8a7'
    },
    'twitter': {
        'id': '3RzWQclolxWZIMq5LJqzRZPTl',
        'secret': 'm9TEd58DSEtRrZHpz2EjrV9AhsBRxKMo8m3kuIZj3zLwzwIimt'
    },
    'cilogon': {
        'id': 'myproxy:oa4mp,2012:/client_id/84e7951a567243a62ae8bc3e13c12c8',
        'secret': 'BK2CDBn-FTbYheNs7dz5neKrYKLVcLmd7Ea-ut1Mgzf8c4Bc4NJ2jIi0H6y4vdur17P-4_Hm50d74CyUdXwcDsOF7ds3I9fKjuwVIdYzc37Olu_oCU0xdWW2nJS36WGYiMZ59LtMueVriL4kyUh34YX34g7a8RVu_rPK8Db_vPkN5uIJ_APHbIxTBS6ASoK3N8aRFtkDfxX27Sl2QIQx2RHrd5A8vRh8TLP7rfAlyq6ttjy8Qibqmx35XgWb-ngKy3NyLZM2y8XdiTEBY88r1heFY9ap2A4I6w3IRfoLc4oTjf5weXK9h6yDOthKjBoiR067Ae0GgJXQDyTjbqA4SUee'
    }
}

db = SQLAlchemy(app)
lm = LoginManager(app)
lm.login_view = 'index'


class DictSerializableMixin(object):
    def serialize(self):
        return self._asdict()

    def _asdict(self):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            result[key] = self._pytype(getattr(self, key))
        return result

    def _pytype(self, v):
        if isinstance(v, datetime):
            return v.isoformat()
        return v

__schema__ = 'ooiui'

# class User(UserMixin, db.Model):
#     __tablename__ = 'users'
#     id = db.Column(db.Integer, primary_key=True)
#     social_id = db.Column(db.String(64), nullable=False, unique=True)
#     nickname = db.Column(db.String(64), nullable=False)
#     email = db.Column(db.String(64), nullable=True)

class Organization(db.Model, DictSerializableMixin):
    __tablename__ = 'organizations'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.Text, nullable=False)
    organization_long_name = db.Column(db.Text)
    image_url = db.Column(db.Text)

    users = db.relationship(u'User')

    @staticmethod
    def insert_org():
        org = Organization.query.filter(Organization.organization_name == 'RPS ASA').first()
        if org is None:
            org = Organization(organization_name = 'RPS ASA')
            db.session.add(org)
            db.session.commit()


class UserScopeLink(db.Model):
    __tablename__ = 'user_scope_link'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.ForeignKey(u'' + __schema__ + '.users.id'), nullable=False)
    scope_id = db.Column(db.ForeignKey(u'' + __schema__ + '.user_scopes.id'), nullable=False)

    scope = db.relationship(u'UserScope')
    user = db.relationship(u'User')

    @staticmethod
    def insert_scope_link():
        usl = UserScopeLink(user_id='1')
        usl.scope_id='1'
        db.session.add(usl)
        db.session.commit()

    def to_json(self):
        json_scope_link = {
            'id' : self.id,
            'user_id' : self.user_id,
            'scope_id' : self.scope_id,
        }
        return json_scope_link

    def __repr__(self):
        return '<User %r, Scope %r>' % (self.user_id, self.scope_id)


class UserScope(db.Model, DictSerializableMixin):
    __tablename__ = 'user_scopes'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    scope_name = db.Column(db.Text, nullable=False, unique=True)
    scope_description = db.Column(db.Text)

    @staticmethod
    def insert_scopes():
        scopes = {
            'redmine',
            'asset_manager',
            'user_admin',
            'annotate',
            'command_control',
            'organization'
            }
        for s in scopes:
            scope = UserScope.query.filter_by(scope_name=s).first()
            if scope is None:
                scope = UserScope(scope_name=s)
            db.session.add(scope)
        db.session.commit()

    def to_json(self):
        json_scope = {
            'id' : self.id,
            'scope_name' : self.scope_name,
            'scope_description' : self.scope_description,
        }
        return json_scope

    def __repr__(self):
        return '<Scope ID: %r, Scope Name: %s>' % (self.id, self.scope_name)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    __table_args__ = {u'schema': __schema__}

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Text, unique=True, nullable=False)
    pass_hash = db.Column(db.Text)
    email = db.Column(db.Text, unique=True, nullable=False)
    user_name = db.Column(db.Text, unique=True, nullable=False)
    active = db.Column(db.Boolean, nullable=False, server_default=db.text("false"))
    confirmed_at = db.Column(db.Date)
    first_name = db.Column(db.Text)
    last_name = db.Column(db.Text)
    phone_primary = db.Column(db.Text)
    phone_alternate = db.Column(db.Text)
    role = db.Column(db.Text)
    email_opt_in = db.Column(db.Boolean, nullable=False, server_default=db.text("true"))
    organization_id = db.Column(db.ForeignKey(u'' + __schema__ + '.organizations.id'), nullable=False)
    scopes = db.relationship(u'UserScope', secondary=UserScopeLink.__table__)
    organization = db.relationship(u'Organization')
    watches = db.relationship(u'Watch')

   # def __init__(self, **kwargs):
   #     super(User, self).__init__(**kwargs)
   #         self.scope = Scope.query.filter_by(scope_name='user_admin').first()
   #         if self.scope is None:
   #             self.scope = Role.query.filter_by(default=True).first()

    def to_json(self):
        json_user = {
            'id' : self.id,
            'user_id' : self.user_id,
            'email' : self.email,
            'active' : self.active,
            'first_name' : self.first_name,
            'last_name' : self.last_name,
            'phone_primary' : self.phone_primary,
            'phone_alternate' : self.phone_alternate,
            'role' : self.role,
            'organization_id' : self.organization_id,
            'scopes' : [s.scope_name for s in self.scopes],
            'user_name' : self.user_name,
            'email_opt_in' : self.email_opt_in
        }
        if self.organization:
            json_user['organization'] = self.organization.organization_name
        return json_user

    @staticmethod
    def from_json(json):
        email = json.get('email')
        password = json.get('password')
        password2 = json.get('repeatPassword')
        phone_primary = json.get('primary_phone')
        user_name = json.get('username')
        first_name = json.get('first_name')
        last_name = json.get('last_name')
        role = json.get('role_name')
        organization_id = json.get('organization_id')
        email_opt_in = json.get('email_opt_in')

        #Validate some of the field.

        new_user = User()
        new_user.validate_email(email)
        new_user.validate_username(user_name)
        new_user.validate_password(password, password2)
        pass_hash = generate_password_hash(password)
        #All passes, return the User object ready to be stored.
        return User(email=email,
                    pass_hash=pass_hash,
                    phone_primary=phone_primary,
                    user_name=user_name,
                    user_id=user_name,
                    first_name=first_name,
                    last_name=last_name,
                    organization_id=organization_id,
                    role=role,
                    email_opt_in=email_opt_in)


    @staticmethod
    def insert_user(username='admin', password=None, first_name='First', last_name='Last', email='FirstLast@somedomain.com', org_name='RPS ASA', phone_primary='8001234567'):
        user = User(password=password, first_name=first_name, active=True, email_opt_in=True)
        user.validate_username(username)
        user.validate_email(email)
        user.user_name = username
        user.email = email
        user.user_id = username
        user.last_name = last_name
        user.phone_primary = phone_primary
        org = Organization.query.filter(Organization.organization_name == org_name).first()
        user.organization_id = org.id
        db.session.add(user)
        db.session.commit()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    #Store the hashed password.
    @password.setter
    def password(self, password):
        self.pass_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.pass_hash, password)

    def validate_email(self, field):
        if User.query.filter_by(email=field).first():
            raise ValidationError('Email already in use.')

    def validate_username(self, field):
        if User.query.filter_by(user_name=field).first():
            raise ValidationError('User name already taken.')

    def validate_password(self, password, password2):
        temp_hash = User(password=password)
        if not temp_hash.verify_password(password2):
            raise ValidationError('Passwords do not match')

    # @login_manager.user_loader
    # def load_user(user_id):
    #     return User.query.get(int(user_id))

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def can(self, scope):
        #db.session.query
        return scope in [s.scope_name for s in self.scopes]

    def __repr__(self):
        return '<User: %r, ID: %r>' % (self.user_name, self.id)


class Watch(db.Model, DictSerializableMixin):
    __tablename__ = 'watches'
    __table_args__ = {u'schema' : __schema__}

    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    user_id = db.Column(db.ForeignKey(u'' + __schema__ + '.users.id'), nullable=False)

    user = db.relationship(u'User')
    operator_events = db.relationship(u'OperatorEvent')

    def to_json(self):
        data = self.serialize()
        del data['user_id']
        data['user'] = {
            'first_name': self.user.first_name,
            'last_name' : self.user.last_name,
            'email' : self.user.email
        }
        return data


    @staticmethod
    def from_json(json_post):
        id = json_post.get('id')
        start_time = json_post.get('start_time')
        end_time = json_post.get('end_time')
        user_id = json_post.get('user_id')
        return Watch(id=id, start_time=start_time, end_time=end_time, user_id=user_id)

@lm.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/logout')
def logout():
    msg = logout_user()
    print msg
    return redirect(url_for('index'))


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


# @app.route('/login/authorized')
@app.route('/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    print oauth
    print oauth.callback()
    user_id, username, email = oauth.callback()
    if user_id is None:
        print 'Authentication failed.'
        return redirect(url_for('index'))
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        user = User(user_id=user_id, user_name=username, email=email)
        db.session.add(user)
        db.session.commit()
    login_user(user, True)
    return redirect(url_for('index'))


if __name__ == '__main__':
    # db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5100)
