from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, delete, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import declarative_base
from salt_pepper_hash import hash_password, salted_pepper_password, generate_salt
from flask import session

#db_connection_string = "mysql+pymysql://aryan:1234@34.83.3.64/jovian?charset=utf8mb4"
db_connection_string = "sqlite:///mydb.db"
engine = create_engine(db_connection_string)
Session = sessionmaker(engine)
sess = Session()
Base = declarative_base()
result_dict = []

class Maintable(Base):
  __tablename__ = 'users'

  userid = Column(Integer, primary_key=True, autoincrement=True)
  username = Column(String(50), unique=True, nullable=False)
  password = Column(String(100), nullable=False)
  email = Column(String(100), nullable=False)
  phonenumber = Column(String(20), nullable=False)
  salt = Column(String(20), nullable=False)
  encryptionkey = Column(String(100), nullable=True)

  def __init__(self, username, password, email, phonenumber, salt):
    self.username = username
    self.password = password
    self.email = email
    self.phonenumber = phonenumber
    self.salt = salt

  def __repr__(self):
    return f"User(userid={self.userid}, username={self.username}, email={self.email}, phonenumber={self.phonenumber})"

Base.metadata.create_all(engine, tables=[Maintable.__table__]) 

def get_user_hashed_password_fromdb(username, password):
  user = sess.query(Maintable).filter(Maintable.username == username).first()
  salt = user.salt
  embedded_password = salted_pepper_password(username, password, salt)
  hashed_password = hash_password(embedded_password)
  return hashed_password
                                         

def user_login(username, password):
  hpass = get_user_hashed_password_fromdb(username, password)
  user = sess.query(Maintable).filter((Maintable.username == username) & (Maintable.password == hpass)).first()
  if user:
    return True
  else:
    return False


UserPassword = None
def add_password_for_apps(website, username, password):
  mainusr = session['username']
  global UserPassword
  if not UserPassword:
    class UserPassword(Base):
      __tablename__ = f"password_table_for_user_{mainusr}"
      passwordid = Column(Integer, primary_key=True, autoincrement=True)
      userid = Column(Integer, ForeignKey('users.userid'), nullable=False)
      website = Column(String(100), nullable=False)
      username = Column(String(50), nullable=False)
      password = Column(String(100), nullable=False)

      def __init__(self, website, username, password):
        self.userid = get_user_id(mainusr)
        self.website = website
        self.username = username
        self.password = password

      def __repr__(self):
        return f"({self.website}, {self.username}, {self.password})"
  else: UserPassword.__table__.create(engine, checkfirst=True)
  new_password = UserPassword(website, username, password)
  sess.add(new_password)
  sess.commit()
    

def delete_app_password(password_id):
    uname = session['username']
    global UserPassword
    if not UserPassword:
        class UserPassword(Base):
            __tablename__ = f"password_table_for_user_{uname}"
            passwordid = Column(Integer, primary_key=True, autoincrement=True)
            userid = Column(Integer, ForeignKey('users.userid'), nullable=False)
            website = Column(String(100), nullable=False)
            username = Column(String(50), nullable=False)
            password = Column(String(100), nullable=False)

            def _init_(self, website, username, password):
                self.userid = get_user_id(uname)
                self.website = website
                self.username = username
                self.password = password

            def _repr_(self):
                return f"({self.website}, {self.username}, {self.password})"
    else:
        # Table is already defined, no need to redefine it
        UserPassword.__table__.create(engine, checkfirst=True)
        
    # Delete the password record
    stmt = delete(UserPassword).where(UserPassword.passwordid == password_id)
    sess.execute(stmt)
    sess.commit()


def get_user_id(username):
  user = sess.query(Maintable).filter(Maintable.username == username).first()
  if user:
    return user.userid
  else:
    return None

def get_user_password(username):
  user = sess.query(Maintable).filter(Maintable.username == username).first()
  if user:
    return user.password
  else:
    return None

def get_user_phoneno(username, password):
  hpass = get_user_hashed_password_fromdb(username, password)
  user = sess.query(Maintable).filter((Maintable.username == username) & (Maintable.password == hpass)).first()
  if user:
    return user.phonenumber
  else:
    return None
    
def get_user_email(username, password):
  hpass = get_user_hashed_password_fromdb(username, password)
  user = sess.query(Maintable).filter((Maintable.username == username) & (Maintable.password == hpass)).first()
  if user:
    return user.email
  else:
    return None


def register_new_user():
  username = session['username'] 
  password = session['password']
  email = session['email'] 
  phonenumber = session['phoneno']
  salt = generate_salt()
  embedded_password = salted_pepper_password(username, password, salt)
  hashed_password = hash_password(embedded_password)
  new_user = Maintable(username, hashed_password, email, '+91' + phonenumber, salt)
  sess.add(new_user)
  sess.commit()
  create_custom_table(username)

def load_app_passwords_from_db():
    username = session['username']
    result_dict.clear()  # Clear the result_dict before appending new results
    with engine.connect() as conn:
        query = f"select * from password_table_for_user_{username}"
        result = conn.execute(text(query))
        for row in result.all():
            result_dict.append(row._asdict())
  
    return result_dict


def create_custom_table(username):
  un = username

  class CustomTable(Base):
    __tablename__ = f"password_table_for_user_{un}"

    passwordid = Column(Integer, primary_key=True, autoincrement=True)
    userid = Column(Integer, ForeignKey('users.userid'), nullable=False)
    website = Column(String(100), nullable=False)
    username = Column(String(50), nullable=False)
    password = Column(String(100), nullable=False)

  # Now create the table
  Base.metadata.create_all(engine, tables=[CustomTable.__table__])

#add_password_for_apps('aryankohli2002', 'instagram', 'aryankohli2002', 'insta@123')
#add_password_for_apps('aryankohli2002', 'facebook', 'aryan2002', 'fb@123')
#register_user('arpit', 'lw', 'aw', '+w')
#print(get_user_password('aryan'))
#add_password_for_apps('aryankohli2002', 'Facebook', 'arpitaryan8368', 'hello')
#delete_app_password('aryan', 1)
# pno = get_user_phoneno(username='aryankohli2002', password='lloyd@3203')
# print(pno)
#print(user_login('aryankohli2002','lloyd@3203'))

# def load_app_passwords_from_db(username):
#   with engine.connect() as conn:
#     query = f"select * from password_table_for_user_{username}"
#     result = conn.execute(text(query))
#     for row in result.all():
#       result_dict.append(row._asdict())
  
#   return result_dict


# result = load_app_passwords_from_db('aryankohli2002')

# for r in result:
#   print(r['website'])