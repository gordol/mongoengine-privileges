


from mongoengine import *
import mongoengine_privileges

class Privilege( EmbeddedDocument ):
    '''
    A class that contains a mapping between a principal (a person or a group) and their permissions
    for the Document it's embedded into.
    '''

    permissions = ListField( StringField() )
    user = ObjectIdField()
    group = StringField()

    def set( self, permissions ):
        """
        Set `permissions` on this Privilege. Replaces all previous `permissions`.

        @param permissions:
        @type permissions: string or list or tuple
        @return:
        """
        if isinstance( permissions, str ):
            permissions = [ permissions ]

        self.permissions = permissions

    def add( self, permissions ):
        """
        Add permissions to this Privilege

        @param permissions:
        @type permissions: string or list or tuple
        @return:
        """
        if isinstance( permissions, str ):
            permissions = [ permissions ]

        self.permissions = list( set( self.permissions ).union( permissions ) )

    def remove( self, permissions ):
        """
        Remove permissions from this Privilege

        @param permissions:
        @type permissions: string or list or tuple
        @return:
        """
        if isinstance( permissions, str ):
            permissions = [ permissions ]

        self.permissions = list( set( self.permissions ).difference( permissions ) )

    def __unicode__( self ):
        return str( 'user={}, group={}: {}'.format( self.user, self.group, self.permissions ) )

