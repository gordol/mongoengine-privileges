from __future__ import print_function
from __future__ import unicode_literals


def monkeypatch_method(cls):
    """
    Add the decorated method to the given class; replace as needed.
    If the named method already exists on the given class, it will
    be replaced, and a reference to the old method appended to a list
    at cls._old_<name>. If the "_old_<name>" attribute already exists
    and is not a list, KeyError is raised.

    See http://mail.python.org/pipermail/python-dev/2008-January/076194.html
    """
    def decorator(func):
        fname = func.__name__

        old_func = getattr(cls, fname, None)
        if old_func is not None:
            # Add the old func to a list of old funcs.
            old_ref = "_old_%s" % fname
            old_funcs = getattr(cls, old_ref, None)
            if old_funcs is None:
                setattr(cls, old_ref, [])
            elif not isinstance(old_funcs, list):
                raise KeyError("%s.%s already exists." % (cls.__name__, old_ref))
            getattr(cls, old_ref).append(old_func)

        setattr(cls, fname, func)
        return func
    return decorator


from mongoengine import Document
from bson import ObjectId

last_id = 0

def get_object_id():
    global last_id
    last_id += 1
    return ObjectId( unicode( last_id ).zfill( 24 ) )


class FauxSave( object ):
    '''
    An object that monkey patches several Document methods that require database interaction,
    so that they doesn't actually persist objects in the database (useful for testing).
    Document.__str__ is also overridden for more useful debug output if __unicode__ isn't overriden
    in implementing documents.
    '''

    last_id = 1

    @monkeypatch_method( Document )
    def save( self, *args, **kwargs ):
        if self.pk is None:
            self.pk = get_object_id()

    @monkeypatch_method( Document )
    def update( self, **kwargs ):
        pass

    @monkeypatch_method( Document )
    def delete( self, **kwargs ):
        pass

    @monkeypatch_method( Document )
    def __str__( self ):
        name = self.__class__.__name__

        if hasattr( self, 'name' ):
            name += ':' + unicode( self.name )

        return '{} ({}@{})'.format( name, self.pk, id( self ) )


class Struct( object ):
    def __init__( self, **entries ):
        self.__dict__.update( entries )

    def __eq__( self, other ):
        return self.__dict__ == other.__dict__

    def __ne__( self, other ):
        return not self.__eq__( other )


def get_mock_request( user, request=None, settings=None ):
    '''
    Create (and fill) a mock request object, useful when needing to save initial data or to save data
    on behalf of another person.

    Be aware it's limited in functionality; because we replace the config (and auth policies),
    stuff like routing (`request.route_url`) and other things attached to the registry (mailer)
    will fail.

    @param user:
    @param request: if supplied, this request will be modified with new auth policies instead of creating a dummy request.
        It's settings (`request.registry.settings`) are also used, unless the `settings` parameter is given.
    @param settings: application settings to use. For a regular request, these can be accessed by `request.registry.settings`
    @return:
    '''
    from pyramid.authorization import ACLAuthorizationPolicy
    from pyramid.request import Request
    from mongoengine_relational import DocumentCache
    from pyramid import testing

    if not request:
        request = Request.blank( '/api/v1/' )

        # Instantiate a DocumentCache; it will attach itself to `request.cache`.
        DocumentCache( request )
    elif not settings:
        settings = request.registry.settings

    request.user = user

    # Set up a mock config. Set the authentication policy to the generated securitypolicy, so it will identify
    # the correct user on `authenticated_id` and `unauthenticated_id`.
    # The authorization policy is set to a new ACL policy; setting this to the generated securitypolicy would
    # allow anything to pass (or fail, with `permissive=False`).
    config = testing.setUp( request=request, settings=settings )
    policy = config.testing_securitypolicy( userid=str( user.pk ) ) #, permissive=True )
    config.set_authentication_policy( policy )
    config.set_authorization_policy( ACLAuthorizationPolicy() )

    request.registry = config.registry

    return request