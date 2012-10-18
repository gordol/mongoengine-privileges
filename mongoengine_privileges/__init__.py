__author__ = 'Progressive Company'
__version__ = (0, 1, 1)

# The default result for the `create` permission.
may_create_default = False


import mongoengine_privileges.privilegemixin
from mongoengine_privileges.privilegemixin import PrivilegeMixin, Privilege, PermissionError
