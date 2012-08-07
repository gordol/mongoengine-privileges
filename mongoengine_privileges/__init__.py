__author__ = 'Progressive Company'
__version__ = (0, 1, 1)

# TODO: make the document someone uses as their `user` configurable
user_document = 'Person'

# The default result for the `create` permission.
may_create_default = False


import mongoengine_privileges.privilegemixin
from mongoengine_privileges.privilegemixin import PrivilegeMixin, Privilege, PermissionError
