from __future__ import print_function
from __future__ import unicode_literals

import unittest

from tests_mongoengine_privileges.utils import FauxSave, Struct, get_object_id, get_mock_request

from pyramid import testing
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.response import Response
from pyramid.request import Request

from mongoengine import *
import mongoengine
from mongoengine_relational import *
from mongoengine_privileges import *


class SimplePrivilegedDocument( PrivilegeMixin, Document ):
    name = StringField()


class PrivilegedDocument( PrivilegeMixin, Document ):
    name = StringField()

    meta = {
        'permissions': {
            'create': 'create',
            'update': 'update'
        }
    }

    def on_change_pk( self, request, new_value, prev_value, updated_fields ):
        print( ('pk updated; current={}, previous={}').format( new_value, prev_value ) )
        self.set_permissions( [ 'view', 'update' ], request.user )

    def may_create( self, request ):
        return True

    def may_update( self, request ):
        return False


class Person( PrivilegeMixin, Document ):
    name = StringField()
    email = StringField( required=True )


class Directory( PrivilegeMixin, Document ):
    name = StringField( required=True )
    files = ListField( ReferenceField( 'File' ), related_name='directory' ) # hasmany relation

    meta = {
        'permissions': {
            'create': 'create',
            'update': 'update',
            'files': 'update_files',
            'name': 'update_name',
            'delete': ''
        }
    }

    may_update_files_called = 0
    on_change_called = 0
    may_delete_called = 0

    def may_update_files( self, request ):
        print( 'may_update_files_called called for `{}`'.format( self ) )
        self.may_update_files_called += 1
        return True

    def may_create( self, request ):
        return True

    def may_delete( self, request ):
        return True

    def on_change_pk( self, request, pk, noop, **kwargs ):
        self.set_permissions( [ 'update', 'update_name' ], request.user )

    def on_change( self, request, changed_fields, updated_fields ):
        self.on_change_called += 1


class File( PrivilegeMixin, Document ):
    name = StringField( required=True )
    type = StringField()
    directory = ReferenceField( 'Directory', related_name='files', required=True ) # hasmany relation

    def may_create( self, request ):
        return True

    def on_change_directory( self, request, value, prev_value, **kwargs ):
        print( ('directory updated; current={}, previous={}').format( value, prev_value ) )
    
    

class PrivilegeTestCase( unittest.TestCase ):

    def setUp( self ):
        # Setup data
        d = self.data = Struct()

        # Setup application/request config
        user_id = get_object_id()
        d.p1 = Person( id=user_id, name='p1', email='p1@progressivecompany.com', groups=[ 'g:deliverable1' ] )
        self.request = get_mock_request( d.p1 )

    def tearDown( self ):
        testing.tearDown()

        # Clear our references
        self.data = None

    def test_get_privilege( self ):
        self.assertEqual( len( self.request.user.privileges ), 0 )

        # Create a `privilege` for a user, then check if `get_privilege` return the correct  `privilege`
        priv = self.request.user.get_privilege( self.request.user, create=True )
        self.assertEqual( priv.user, self.request.user.pk )
        self.assertEqual( len( priv.permissions ), 0 )

        # Create a `privilege` for a group, then check if `get_privilege` return the correct  `privilege`
        group = 'g:' + str( get_object_id() )
        priv = self.request.user.get_privilege( group, create=True )
        self.assertEqual( priv.group, group )
        self.assertEqual( len( priv.permissions ), 0 )

        self.assertEqual( len( self.request.user.privileges ), 2 )

        self.request.user.remove_privilege( group )

        self.assertEqual( len( self.request.user.privileges ), 1 )


    def test_add_remove_permission( self ):
        priv = Privilege( user=self.request.user.id )

        priv.add( 'view' )

        self.assertIn( 'view', priv.permissions )

        priv.add( [ 'create', 'edit' ] )

        self.assertEqual( len( priv.permissions ), 3 )

        self.assertIn( 'edit', priv.permissions )

        priv.remove( [ 'view', 'edit' ] )

        self.assertNotIn( 'edit', priv.permissions )


    def test_add_remove_privilege( self ):
        doc = PrivilegedDocument()
        self.assertFalse( doc.privileges )

        doc.get_privilege( self.request.user, create=True )
        self.assertTrue( doc.privileges )

        doc.remove_privilege( self.request.user )
        self.assertFalse( doc.privileges )

        group = 'g:0000000001'
        doc.get_privilege( group )
        self.assertFalse( doc.privileges )

        doc.get_privilege( group, create=True )
        self.assertTrue( doc.privileges )

        doc.remove_privilege( group )
        self.assertFalse( doc.privileges )


    def test_on_change( self ):
        doc = PrivilegedDocument()

        self.assertFalse( doc.may( self.request, 'view' ) )
        self.assertTrue( doc.may( self.request, 'create' ) )

        doc.save( request=self.request )

        print( self.request, self.request.user )
        print( doc.privileges )

        self.assertTrue( doc.may( self.request, 'view' ) )

    def test_meta( self ):
        # doc doesn't have explicit permissions set; uses the `default_permissions`
        simple_doc = SimplePrivilegedDocument()
        self.assertEqual( simple_doc.get_permission_for( 'update' ), 'update' )
        self.assertEqual( simple_doc.get_permission_for( 'delete' ), 'delete' )

        doc = PrivilegedDocument()
        permissions = doc._meta[ 'permissions' ]
        self.assertEqual( permissions[ 'update' ], 'update' )


    def test_permission_methods( self ):
        # Create a directory, save it so give it an `id` and set initial permissions
        dir = Directory( name='Code' )
        dir.save( self.request )

        # `update` has been granted
        self.assertTrue( dir.may( self.request, 'update' ) )

        # `bogus` hasn't
        self.assertFalse( dir.may( self.request, 'bogus' ) )

        # `None` and '' are allowed
        self.assertTrue( dir.may( self.request, None ) )
        self.assertTrue( dir.may( self.request, '' ) )

        # `add_file` has been implemented as a method, `may_update_file`
        self.assertTrue( dir.may( self.request, 'update_files' ) )
        self.assertEqual( dir.may_update_files_called, 1 )

        # Create a file, save it so give it an `id` and set initial permissions
        file = File( name='todo.txt', directory=dir )
        file.save( self.request )

        # dir.files is still marked as changed, but only `may_update` is called on `save`
        dir.save( self.request )
        self.assertEqual( dir.may_update_files_called, 1 )

        # the `delete` action doesn't specify a required permission, so `may_delete` won't get called
        self.assertEqual( dir.may_delete_called, 0 )
        dir.delete( self.request )
        self.assertEqual( dir.may_delete_called, 0 )

    def test_update( self ):
        dir = Directory( name='Code' )
        dir.save( self.request )

        self.assertEqual( dir.on_change_called, 1 )

        # Update a field on a document the user has `update` permission on
        f1 = File( name='f1', directory=dir )
        f1.save( self.request )
        dir.update( self.request, 'files' )

        self.assertEqual( dir.on_change_called, 2 )
        self.assertEqual( dir.may_update_files_called, 1 )

        dir.name = 'New code'
        dir.update( self.request, 'name' )

        self.assertEqual( dir.on_change_called, 3 )
        self.assertEqual( dir.may_update_files_called, 1 )

        # Update a field on a document the user doesn't have the `update` permission on
        p2 = Person( id=get_object_id(), name='p2', email='p2@progressivecompany.com' )
        request_p2 = get_mock_request( p2 )

        dir.grant( self.request, 'update_files', p2 )
        self.assertEqual( dir.on_change_called, 4 )

        with self.assertRaises( PermissionError ):
            dir.name = 'Old code'
            dir.update( request_p2, 'name' )

        f2 = File( name='f2', directory=dir )
        f2.save( request_p2 )
        dir.update( request_p2, 'files' )

        self.assertEqual( dir.on_change_called, 5 )
        self.assertEqual( dir.may_update_files_called, 2 )

        # Update two fields on `dir`; `p2` still doesn't have the `update` permission, but may update those two fields
        dir.grant( self.request, 'update_name', p2 )
        self.assertEqual( dir.on_change_called, 6 )

        dir.name = 'Code'
        dir.files.remove( f2 )

        self.assertSetEqual( dir.get_changed_fields(), { 'name', 'files' } )

        dir.save( request_p2 )
        self.assertEqual( dir.on_change_called, 7 )
        self.assertEqual( dir.may_update_files_called, 3 )

    def test_save( self ):
        pass

    def test_update_privileges( self ):
        pass

    def test_grant( self ):
        pass

    def test_revoke( self ):
        pass

