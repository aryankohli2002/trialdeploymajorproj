from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, delete, text, inspect, BINARY
from sqlalchemy.orm import sessionmaker, declarative_base
from salt_pepper_hash import hash_password, salted_pepper_password, generate_salt
from flask import session
from aess import generate_key, encrypt_AES, decrypt_AES
import os

# db_connection_string = "mysql+pymysql://aryan:1234@34.83.3.64/jovian?charset=utf8mb4"
engine = create_engine("sqlite:///mydb.db")
Session = sessionmaker(bind=engine)
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
    encryptionkey = Column(BINARY, nullable=False)

    def __repr__(self):
        return f"Maintable(userid={self.userid}, username={self.username}, email={self.email}, phonenumber={self.phonenumber})"

Base.metadata.create_all(engine, tables=[Maintable.__table__])

def check_if_user_exists(username):
    user = sess.query(Maintable).filter_by(username=username).first()
    return user is not None

def register_new_user():
    username = session['username'] 
    password = session['password']
    email = session['email'] 
    phonenumber = session['phoneno']
    salt = generate_salt()
    embedded_password = salted_pepper_password(username, password, salt)
    hashed_password = hash_password(embedded_password)
    key = generate_key()
    new_user = Maintable(
        username=username,
        password=hashed_password,
        email=email,
        phonenumber='+91' + phonenumber,
        salt=salt,
        encryptionkey=key,
        )
    sess.add(new_user)
    sess.commit()
    class CustomTable(Base):
        username = session['username']
        __tablename__ = f"password_table_for_user_{username}"
        passwordid = Column(Integer, primary_key=True, autoincrement=True)
        website = Column(String(100), nullable=False)
        username = Column(String(50), nullable=False)
        password = Column(String(100), nullable=False)
        nonce = Column(BINARY, nullable=False)
        tag = Column(BINARY, nullable=False)

    Base.metadata.create_all(engine, tables=[CustomTable.__table__])


def check_user_reset_details():
    email = session['email']
    phoneno = session['phoneno']
    user = sess.query(Maintable).filter((Maintable.email == email) & (Maintable.phonenumber == phoneno)).first()
    if user:
        return True
    else:
        return False

def fetch_username_for_password_reset():
    email = session['email']
    phoneno = session['phoneno']
    user = sess.query(Maintable).filter((Maintable.email == email) & (Maintable.phonenumber == phoneno)).first()
    if user:
        return user.username
    else:
        return False


def reset_password():
    username = session['username']
    password = session['password']
    email = session['email']
    phoneno = session['phoneno']
    salt = generate_salt()
    print('new salt:  ', salt)
    embedded_password = salted_pepper_password(username, password, salt)
    hashed_password = hash_password(embedded_password)
    print("hashedpw:  ", hashed_password)
    user = sess.query(Maintable).filter((Maintable.email == email) & (Maintable.phonenumber == phoneno) & (Maintable.username == username)).first()
    if user:
        user.salt = salt
        user.password = hashed_password
        sess.add(user)
        sess.commit()
        return True
    else:
        return False


def get_user_id():
    username = session['username']
    user = sess.query(Maintable).filter(Maintable.username == username).first()
    if user:
        return user.userid
    else:
        return None


def user_login(username, password):
    hpass = get_user_hashed_password_fromdb(username, password)
    user = sess.query(Maintable).filter((Maintable.username == username) & (Maintable.password == hpass)).first()
    if user:
        return True
    else:
        return False


def get_user_hashed_password_fromdb(username, password):
    user = sess.query(Maintable).filter(Maintable.username == username).first()
    salt = user.salt
    embedded_password = salted_pepper_password(username, password, salt)
    hashed_password = hash_password(embedded_password)
    return hashed_password


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

####################################################################################################################################
#                                                   USER PASSWORD TABLE BELOW 
####################################################################################################################################


class CustomerTable(Base):
    __tablename__ = 'customer_table'  # Default table name
    passwordid = Column(Integer, primary_key=True, autoincrement=True)
    website = Column(String(100), nullable=False)
    username = Column(String(50), nullable=False)
    password = Column(String(100), nullable=False)
    nonce = Column(BINARY, nullable=False)
    tag = Column(BINARY, nullable=False)

def get_customer_password_table_name(name):
    tablename = 'password_table_for_user_%s' % name
    class_name = 'CustomerTable%s' % name.capitalize()
    Model = type(class_name, (Base,), {
        '__tablename__': tablename,
        '__table_args__': {'extend_existing': True},
        'passwordid': Column(Integer, primary_key=True, autoincrement=True),
        'website': Column(String(100), nullable=False),
        'username': Column(String(50), nullable=False),
        'password': Column(String(100), nullable=False),
        'nonce':   Column(BINARY, nullable=False),
        'tag' :Column(BINARY, nullable=False),
    })
    return Model

def table_exists(engine, tablename):
    """Check if the table exists in the database."""
    insp = inspect(engine)
    return tablename in insp.get_table_names()

def get_encryption_key_from_Maintable():
    username = session['username']
    if username is None:
        raise ValueError("No username found in session.")
    
    user = sess.query(Maintable).filter(Maintable.username == username).first()
    if user:
        return user.encryptionkey
    else: 
        return False
    
def encryptPassword(password):
    key = get_encryption_key_from_Maintable()
    encrypted_password, nonce, tag = encrypt_AES(password, key)
    return encrypted_password, nonce, tag

def add_password_for_apps(website, username_on_website, password):
    user = session['username']  
    if user is None:
        raise ValueError("No username found in session.")
    # Get dynamic table model
    CustomerTableDynamic = get_customer_password_table_name(user)
    if not table_exists(engine, CustomerTableDynamic.__tablename__):
        # Create the table in the database if it doesn't exist
        CustomerTableDynamic.__table__.create(engine, checkfirst=True)
    
    encrypted_password, nonce, tag = encryptPassword(password)
    new_record = CustomerTableDynamic(
        website=website, 
        username=username_on_website, 
        password=encrypted_password,
        nonce=nonce,
        tag=tag
    )
    sess.add(new_record)
    sess.commit()


def delete_app_password(password_id):
    user = session.get('username')
    if user is None:
        raise ValueError("No username found in session.")

    # Get dynamic table model
    CustomerTableDynamic = get_customer_password_table_name(user)

    # Construct delete query and execute
    delete_query = delete(CustomerTableDynamic).where(CustomerTableDynamic.passwordid == password_id)
    sess.execute(delete_query)
    sess.commit()


def update_app_username(newUsername, passwordid):
    user = session.get('username')
    if user is None:
        raise ValueError("No username found in session.")
    
    CustomerTableDynamic = get_customer_password_table_name(user)

    user = sess.query(CustomerTableDynamic).where(CustomerTableDynamic.passwordid == passwordid).first()
    if user:
        user.username = newUsername
        sess.commit()
        return True
    else: 
        return False


def update_app_password(newPassword, passwordid):
    user = session.get('username')
    if user is None:
        raise ValueError("No username found in session.")
    
    CustomerTableDynamic = get_customer_password_table_name(user)

    user = sess.query(CustomerTableDynamic).where(CustomerTableDynamic.passwordid == passwordid).first()
    if user:
        encrypted_password, nonce, tag = encryptPassword(newPassword)
        user.password = encrypted_password
        user.nonce = nonce
        user.tag = tag
        sess.add(user)
        sess.commit()
        return True
    else: 
        return False


def load_app_passwords_from_db():
    result_dict.clear()  # Clear the result_dict before appending new results
    username = session['username']
    if username is None:
        raise ValueError("No username found in session.")
    
    key = get_encryption_key_from_Maintable()
    with engine.connect() as conn:
        query = f"select * from password_table_for_user_{username}"
        result = conn.execute(text(query))
        for row in result.all():
            encrypted_password = row.password
            nonce = row.nonce
            tag = row.tag
            decrypted_password = decrypt_AES(encrypted_password, nonce, tag, key)
            row_dict = row._asdict()
            row_dict['dpassword'] = decrypted_password
            result_dict.append(row_dict)

    return result_dict

# def load_app_passwords_from_db():
#     result_dict.clear()  # Clear the result_dict before appending new results
#     username = session['username']
#     if username is None:
#         raise ValueError("No username found in session.")
    
#     key = get_encryption_key_from_Maintable()
#     with engine.connect() as conn:
#         query = f"select * from password_table_for_user_{username}"
#         result = conn.execute(text(query))
#         for row in result.all():
#             result_dict.append(row._asdict())

#     return result_dict
