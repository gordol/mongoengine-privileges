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
