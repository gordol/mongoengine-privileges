from __future__ import print_function
from __future__ import unicode_literals


class ApplicationException( Exception ):
    """A base exception for other application errors."""

    def __init__( self, message='', code=0, *args, **kwargs ):
        super( ApplicationException, self ).__init__( message, *args, **kwargs )
        if code > 0:
            self.code = code

class PermissionError( ApplicationException ):
    def __init__( self, attribute_name, permission='?' ):
        # Determine the name of the class throwing the error
        import inspect
        frame, module, line, function, context, index = inspect.stack()[1]
        self_argument = frame.f_code.co_varnames[ 0 ]  # This *should* be 'self'.
        instance = frame.f_locals[ self_argument ]
        class_name = instance.__class__.__name__

        message = "Permission denied; `{}` required for {}.{}".format( permission, class_name, attribute_name )
        super( PermissionError, self ).__init__( message, code=100 )

