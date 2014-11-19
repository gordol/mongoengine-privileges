from __future__ import print_function
from __future__ import unicode_literals

import logging
import collections

log = logging.getLogger(__name__)

class ApplicationException( Exception ):
    """A base exception for other application errors."""

    def __init__( self, message='', code=0, *args, **kwargs ):
        super( ApplicationException, self ).__init__( message, *args, **kwargs )
        if code > 0:
            self.code = code

class PermissionError( ApplicationException ):
    def __init__( self, request, attribute_name, permission='?' ):
        # Determine the name of the class throwing the error
        import inspect
        frame, module, line, function, context, index = inspect.stack()[1]
        self_argument = frame.f_code.co_varnames[ 0 ]  # This *should* be 'self'.
        instance = frame.f_locals[ self_argument ]
        class_name = instance.__class__.__name__

        if not isinstance( attribute_name,  basestring ) and isinstance( attribute_name, collections.Iterable ):
            if len( attribute_name ) == 1:
                attribute_name = list( attribute_name )[ 0 ]
            else:
                attribute_name = '(' + ', '.join( attribute_name ) + ')'

        message = "Permission denied; `{}` required for {}.{}".format( permission, class_name, attribute_name )
        log.info( 'PermissionError for user id="{}" on {} id="{}". Message="{}"'.format( request.user.id, class_name, instance.id, message ) )
        super( PermissionError, self ).__init__( message, code=100 )

