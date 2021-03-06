from __future__ import print_function
from __future__ import unicode_literals

import inspect

from pyramid.security import ( Allow, DENY_ALL, has_permission )
from pyramid.request import Request

from mongoengine import *
from mongoengine_relational import RelationManagerMixin
from bson import DBRef, ObjectId

from .exceptions import PermissionError
from .privilege import Privilege

import mongoengine_privileges


class PrivilegeMixin( RelationManagerMixin ):
    '''
    A class that adds `Privileges` to a Document when inheriting from it.
    '''

    default_permissions = {
        'create': 'create',
        'update': 'update',
        'delete': 'delete'
    }

    privileges = ListField( EmbeddedDocumentField( 'Privilege' ) )

    def save( self, request=None, force_insert=False, validate=True, clean=True, write_concern=None,
            cascade=None, cascade_kwargs=None, _refs=None, **kwargs ):
        '''
        Overridden save. Checks permissions for the `update` action, or for individual relations if the `request.user`
        is not allowed to update the Document as a whole.
        '''
        request = request or ( kwargs and '_request' in kwargs and kwargs[ '_request' ] ) or self._request or None

        if not request:
            raise ValueError( '`save` needs a `request` parameter (in order to properly invoke `may_*` and `on_change*` callbacks)' )
        elif not isinstance( request, Request ):
            raise ValueError( 'request=`{}` should be an instance of `pyramid.request.Request`'.format( request ) )

        if self.pk is None:
            permission = self.get_permission_for( 'create' )
        else:
            permission = self.get_permission_for( 'update' )

        # A document may be saved if:
        # - it's new,
        # - the required permission for this action has been explicitly set to an empty string (''),
        # - or the user has the appropriate permission
        if self.may( request, permission ):
            # Run validation now, since we can pass it `request` so it can check permissions.
            if validate:
                self.validate()
                # Stuff `validate` in `kwargs`, so `cascade_save` will receive it
                kwargs = kwargs or {}
                kwargs.setdefault( 'validate', validate )
                validate = False

            return super( PrivilegeMixin, self ).save( request=request, force_insert=force_insert, validate=validate,
                clean=clean, write_concern=write_concern, cascade=cascade, cascade_kwargs=cascade_kwargs, _refs=_refs, kwargs=kwargs )
        elif self.pk:
            #  Try to save individual fields (relations), since the user may have permission(s) to save these,
            # instead of the complete object.
            # `changed_fields` can also be empty; in that case, just continue (without an error). This may mean
            # that whatever change triggered the call to `save` has been taken care of already by business logic.
            changed_fields = self.get_changed_fields()
            if changed_fields:
                self.update( request, *changed_fields )
        else:
            raise PermissionError( request, 'save', permission )

    def update( self, request, *args, **kwargs ):
        '''
        Update one or more fields on this document. If a `field_name` is given, the appropriate permission
        for the given `field_name` is checked; only that field will be updated.
        If `field_name` is not given, the permission required to `update` the document will be checked.

        @param request:
        @type request: pyramid.request.Request
        @param args: a list of field names that should be updated
        @return:
        '''
        if not isinstance( request, Request ):
            raise ValueError( 'request=`{}` should be an instance of `pyramid.request.Request`'.format( request ) )

        permissions = set()

        if not args:
            permissions.add( self.get_permission_for( 'update' ) )
        else:
            for field_name in args:
                if not getattr( self, field_name, None ):
                    AttributeError( 'Cannot resolve field={} on {}'.format( field_name, self ) )

                # See if an explicit permission has been configured for `field_name`.
                # An empty string or False mean no permission is required. `None` means no explicit permission has been
                # defined; in that case, we'll want to check the default permission for update.
                permission = self.get_permission_for( field_name )

                if permission is None:
                    permission = self.get_permission_for( 'update' )

                permissions.add( permission )

        # Check `permission`, and update if we're allowed to (if `permission` is `None`, that means it's allowed).
        for permission in permissions:
            if not self.may( request, permission ):
                raise PermissionError( request, args, permission )

        return super( PrivilegeMixin, self ).update( request, *args, **kwargs )

    def update_privileges( self, request ):
        '''
        Explicitly update `privileges` only. This bypasses any further security checks!

        @param request:
        @type request: Request
        @return:
        '''
        super( PrivilegeMixin, self ).update( request, 'privileges' )

    def delete( self, request, **write_concern ):
        '''
        Overridden `delete`. Checks if the current user has the appropriate `delete` privilege to execute this action.

        @param request:
        @type request: Request
        '''
        permission = self.get_permission_for( 'delete' )
        if self.may( request, permission ):
            return super( PrivilegeMixin, self ).delete( request=request, write_concern=write_concern )
        else:
            raise PermissionError( request, 'delete', permission )

    @property
    def __acl__( self ):
        acl = []

        for priv in self.privileges:
            user = priv[ 'user' ]
            principal = priv.group

            if user:
                if isinstance( user, ObjectId ):
                    principal = user
                elif isinstance( user, DBRef ):
                    principal = user.id
                elif isinstance( user, Document ):
                    principal = user.pk

            if principal:
                acl.append( ( Allow, str( principal ), priv.permissions ) )

        # Everything that's not explicitly allowed is forbidden; add a final DENY_ALL
        acl.append( DENY_ALL )

        #print( 'acl for {}={}'.format( self, acl ) )

        return acl

    def get_permission_for( self, name ):
        '''
        @param name: the name of the field for which to look up the appropriate permission
        @return:
        @rtype: string
        '''
        permissions = self._meta.get( 'permissions', self.default_permissions )
        return permissions.get( name, None )

    def may( self, request, permission ):
        '''
        Check if the current user is allowed to execute `permission` on this Document.

        More complex permissions may be implemented as a method, instead of simply checking for existence of
        the permission. If so, this method is invoked and it's result is returned.

        Methods implementing `may_*` should have the following signature: ( permission<str>, user<User> )

        @param request: the Request object
        @type request: pyramid.request.Request
        @param permission:
        @type permission: string
        @return:
        @rtype: bool
        '''
        # Empty/false permissions may pass
        if not permission:
            return True

        method = getattr( self, 'may_{}'.format( permission ), None )

        if callable( method ):
            result = method( request )
        else:
            result = has_permission( permission, self, request )

        return result

    def may_create( self, request ):
        '''
        Default implementation for `may_create`, so `create` will be allowed by default.

        @param request:
        @return:
        '''
        return mongoengine_privileges.may_create_default

    def grant( self, request, permissions, principal ):
        '''
        Add permissions for the given principal, and persists the updated
        privileges right away. The permission check for updating the Document
        is performed before actually removing the permissions.

        @param permissions:
        @type permissions: string or list or tuple
        @param principal:
        @param request:
        @return:
        '''
        permission = self.get_permission_for( 'update' )

        if self.may( request, permission ):
            self.add_permissions( permissions, principal )
            return self.update_privileges( request )

    def revoke( self, request, permissions, principal ):
        '''
        Remove permissions for the given principal, and persists the updated
        privileges right away. The permission check for updating the Document
        is performed before actually removing the permissions, so `revoke` can
        be used to remove the privilege required for `update`.

        @param permissions:
        @type permissions: string or list or tuple
        @param principal:
        @return:
        '''
        permission = self.get_permission_for( 'update' )

        if self.may( request, permission ):
            self.remove_permissions( permissions, principal )
            return self.update_privileges( request )

    def set_permissions( self, permissions, principal ):
        '''
        Set permissions, as a (list of) strings, for the given `user`.
        This replaces any previous `permissions` that might be present for
        `user`. This method modifies the `privileges` field on the Document,
        but doesn't persist changes yet.

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
        Add permissions for a `principal`, as a (list of) strings. This method
        modifies the `privileges` field on the Document, but doesn't persist
        changes yet.

        @type permissions: string or list or tuple
        @type principal: User or string or Privilege
        @return:
        @rtype: Privilege
        '''
        privilege = self.get_privilege( principal, create=True )
        privilege.add( permissions )
        return privilege

    def remove_permissions( self, permissions, principal ):
        '''
        Remove permissions for a `principal`, as a (list of) strings. This
        method modifies the `privileges` field on the Document, but doesn't
        persist changes yet.

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
        Get the Privilege object on this Document for a given `principal`,
        which can be either a `User` or a group name. If it doesn't exist yet,
        creates a new Privilege and adds it to `self.privileges`.

        This method modifies the `privileges` field on the Document, but
        doesn't persist changes yet.


        @param principal:
        @type principal: User or string or Privilege
        @return:
        @rtype: Privilege
        '''
        if isinstance( principal, Privilege ):
            return principal

        privilege = None

        for priv in self.privileges:
            # Get the correct privilege.
            if priv.group == principal or ( isinstance( principal, Document ) and principal.pk and principal.pk == priv[ 'user' ] ):
                privilege = priv
                break

        if not privilege and create:
            user = principal.pk if isinstance( principal, Document ) else None
            group = principal if isinstance( principal, basestring ) else None

            if not user and not group:
                raise AttributeError( 'Either a user or group is needed to create a `Privilege`' )

            privilege = Privilege( user=user, group=group )
            self.privileges.append( privilege )

        return privilege

    def remove_privilege( self, principal ):
        '''
        Remove all `permissions` (the complete `privilege`) from this Document
        for the given `principal`. This method modifies the `privileges` field
        on the Document, but doesn't persist changes yet.

        @param principal: User or string or Privilege
        @return:
        '''
        privilege = self.get_privilege( principal )
        privilege and self.privileges.remove( privilege )

    def clear_privileges( self ):
        '''
        Remove all existing privileges (and thus permissions) from this Document.
        This method modifies the `privileges` field on the Document, but
        doesn't persist changes yet.
        @return:
        '''
        self.privileges = []
