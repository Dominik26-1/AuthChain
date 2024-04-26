# class syntax
from enum import Enum

from certificate.action_verifier import verify_signup, verify_login, verify_update, verify_logout


class Action(Enum):
    LOGIN = ("LOGIN", verify_login, "/login", "/accept_login")
    LOGOUT = ("LOGOUT", verify_logout, "/logout", "/accept_logout")
    SIGNUP = ("SIGNUP", verify_signup, "/register", "/accept_registration")
    UPDATE = ("UPDATE", verify_update, "/update", "/accept_update")
    CREATE = ("CREATE", verify_signup, "/create", "/accept_create")
