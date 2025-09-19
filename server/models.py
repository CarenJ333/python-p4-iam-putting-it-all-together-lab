from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import Column, Integer, String, ForeignKey


from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    _password_hash = Column(String, nullable=False, default=bcrypt.generate_password_hash("default123").decode("utf-8"))
    image_url = Column(String)
    bio = Column(String)

    # relationships

    recipes = relationship("Recipe", back_populates="user", cascade="all, delete-orphan")


    # Prevent direct access to password
    @property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    # Setter to hash password before saving
    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    # Check password validity
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    # Validation for username
    @validates('username')
    def validate_username(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Username must be present.")
        return value

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    instructions = Column(String, nullable=False)
    minutes_to_complete = Column(Integer, nullable=False)

    # foreign key (recipe belongs to a user)
    user_id = Column(Integer, ForeignKey('users.id'))

    # relationship back to User
    user = relationship("User", back_populates="recipes")
    

    @validates("title")
    def validate_title(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Recipe title must be present.")
        return value

    @validates("instructions")
    def validate_instructions(self, key, value):
        if not value or value.strip() == "":
            raise ValueError("Recipe instructions must be present.")
        if len(value.strip()) < 50:
            raise ValueError("Recipe instructions must be at least 50 characters long.")
        return value