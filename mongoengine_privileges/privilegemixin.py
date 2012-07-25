from __future__ import print_function
from __future__ import unicode_literals

import inspect

from pyramid.security import ( Allow, DENY_ALL, has_permission )
from pyramid.request import Request

from mongoengine import *
from mongoengine_relational import RelationManagerMixin
from bson import DBRef

from .exceptions import PermissionError
from .privilege import Privilege


class PrivilegeMixin( RelationManagerMixin ):
    '''
    A class that adds `Privileges` to a Document when inheriting from it.
    '''

    default_permissions = {
        'update': 'update',
        'delete': 'delete'
    }

    privileges = ListField( EmbeddedDocumentField( 'Privilege' ) )

    def save( self, safe=True, force_insert=False, validate=True, write_options=None, cascade=None, cascade_kwargs=None, _refs=None, request=None ):
        request = request or ( cascade_kwargs and cascade_kwargs[ 'request' ] ) or None

        if not request:
            raise ValueError( '`save` needs a `request` parameter (in order to properly invoke `may_*` and `on_change*` callbacks)' )

        permission = self.get_permission_for( 'update' )

        # A document may be saved if:
        # - it's new,
        # - the required permission for this action has been explicitly set to an empty string (''),
        # - or the user has the appropriate permission
        if self.pk is None or permission == '' or ( permission and self.may( permission, request ) ):

            # Run validation now, since we can pass it `request` so it can check permissions.
            if validate:
                self.validate( request=request )
                # Stuff `validate` in `cascade_kwargs`, so `cascade_save` will receive it as a kwarg
                cascade_kwargs = cascade_kwargs or {}
                cascade_kwargs.setdefault( 'validate', validate )
                validate = False

            return super( PrivilegeMixin, self ).save( safe=safe, force_insert=force_insert, validate=validate,
                write_options=write_options, cascade=cascade, cascade_kwargs=cascade_kwargs, _refs=_refs, request=request )
        else:
            raise PermissionError( 'update', permission )


    def update( self, request, field_name=None, require_caller_update=True, **kwargs ):
        '''
        Update one or more fields on this document. When updating a single field,
        '''
        if field_name is None:
            permission = self.get_permission_for( 'update' )
        else:
            permission = self.get_permission_for( field_name )

            kwargs[ 'set__{}'.format( field_name ) ] = self[ field_name ]

            # Check if the request.user is allowed to update the document calling `update` on this document.
            if require_caller_update:
                source_object = inspect.stack()[ 1 ][ 0 ].f_locals[ 'self' ]
                permission = self.get_permission_for( 'update' )
                if not source_object.may( permission, request ):
                    raise PermissionError( 'update_{}'.format( field_name ), permission )

        if permission == '' or ( permission and self.may( permission, request ) ):
            return super( PrivilegeMixin, self ).update( **kwargs )
        else:
            raise PermissionError( 'update', permission )

    def update_privileges( self, request ):
        '''
        Explicitly update `privileges` ONLY; this bypasses other security.
        However, the current `request.user` MUST be allowed to update the Document that is trying to modify
        the `privileges` on this Document.

        @param request:
        @type request: Request
        @return:
        '''
        self.update( request, 'privileges' )

    def delete( self, request, safe=False ):
        '''
        Overridden `delete`.

        @param request:
        @type request: Request
        '''
        permission = self.get_permission_for( 'delete' )
        if permission == '' or ( permission and self.may( permission, request ) ):
            return super( PrivilegeMixin, self ).delete( safe=safe )
        else:
            raise PermissionError( 'delete', permission )

    def validate( self, request ):
        '''
        Overridden `validate`. Checks individual permissions on relational fields.

        @param request:
        @type request: Request
        '''
        # Check permissions if the document exists
        if self.pk:
            changed_relations = self.get_changed_relations()

            for relation_name in changed_relations:
                permission = self.get_permission_for( relation_name )
                if permission and not self.may( permission, request ):
                    raise PermissionError( relation_name, permission )

        return super( PrivilegeMixin, self ).validate()

    @property
    def __acl__( self ):
        acl = []

        for priv in self.privileges:
            user = priv._data[ 'user' ]
            user_id = user and ( user.id if isinstance( user, DBRef ) else user.pk )
            acl.append( ( Allow, user_id or priv.group, priv.permissions ) )

        # Everything that's not explicitly allowed is forbidden; add a final DENY_ALL
        acl.append( DENY_ALL )

        #print( 'acl for {}={}'.format( self, acl ) )

        return acl

    def get_permission_for( self, name ):
        permissions = self._meta.get( 'permissions', self.default_permissions )
        return permissions.get( name, None )

    def may( self, permission, request ):
        '''
        Check if the current user is allowed to execute `permission` on this Document.

        More complex permissions may be implemented as a method, instead of simply checking for existence of
        the permission. If so, this method is invoked and it's result is returned.

        Methods implementing `may_*` should have the following signature: ( permission<str>, user<User> )

        @param permission:
        @type permission: string
        @param request: the Request object
        @return:
        @rtype: bool
        '''
        method = getattr( self, 'may_{}'.format( permission ), None )

        if callable( method ):
            result = method( request )
        else:
            result = has_permission( permission, self, request )

        return result

    def set_permissions( self, permissions, principal ):
        '''
        Set permissions, as a (list of) strings, for the given `user`.
        This replaces any previous `permissions` that might be present for
        `user`.

        @param permissions:
        @type permissions: string or list or tuple
        @param principal:
        @type principal: User or string or Privilege
        @return:
        @rtype: Privilege
        '''
        privilege = self.get_privilege( principal, create=True )
        privilege.set( permissions )
        return privilege

    def add_permissions( self, permissions, principal ):
        '''
        Add permissions for a `principal`, as a (list of) strings.

        @param permissions:
        @type permissions: string or list or tuple
        @param principal:
        @type principal: User or string or Privilege
        @return:
        @rtype: Privilege
        '''
        privilege = self.get_privilege( principal, create=True )
        privilege.add( permissions )
        return privilege

    def remove_permissions( self, permissions, principal ):
        '''
        Remove permissions for a `principal`, as a (list of) strings.

        @param permissions:
        @type permissions: string or list or tuple
        @param principal:
        @type principal: User or string or Privilege
        @return:
        @rtype: Privilege
        '''
        privilege = self.get_privilege( principal )
        privilege and privilege.remove( permissions )
        return privilege

    def get_privilege( self, principal, create=False ):
        '''
        Get the Privilege object on this Document for a given `principal`, which can be either
        a `User` or a
        If it doesn't exist yet, creates a new Privilege and adds it to `self.privileges`.

        @param principal:
        @type principal: User or string or Privilege
        @return:
        @rtype: Privilege
        '''
        if isinstance( principal, Privilege ):
            return principal

        privilege = None

        for priv in self.privileges:
            # Get the correct privilege. Checks `user` as a DBRef if possible, instead of dereferencing it.
            if priv.group == principal or ( isinstance( principal, PrivilegeMixin ) and principal._equals( priv._data[ 'user' ] ) ):
                privilege = priv
                break

        if not privilege and create:
            user = principal if isinstance( principal, PrivilegeMixin ) else None
            group = principal if isinstance( principal, basestring ) else None
            privilege = Privilege( user=user, group=group )
            self.privileges.append( privilege )

        return privilege

    def remove_privilege( self, principal ):
        '''
        Remove all `permissions` (the complete `privilege`) from this Document for a `principal`
        @param principal: User or string or Privilege
        @return:
        '''
        privilege = self.get_privilege( principal )
        privilege and self.privileges.remove( privilege )

    def clear_privileges( self ):
        '''
        Remove all existing privileges (and thus permissions) from this Document
        @return:
        '''
        self.privileges = []
