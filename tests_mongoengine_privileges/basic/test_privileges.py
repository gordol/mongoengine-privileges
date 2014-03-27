from __future__ import print_function
from __future__ import unicode_literals

import unittest

from tests_mongoengine_privileges.utils import FauxSave, Struct, get_object_id

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

    def on_change_pk( self, request, new_value, prev_value, field_name ):
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
            'files': 'add_file',
            'delete': ''
        }
    }

    may_add_file_called = 0

    def may_add_file( self, request ):
        print( 'may_add_file called for `{}`'.format( self ) )
        self.may_add_file_called += 1
        return True

    may_delete_called = 0

    def may_create( self, request ):
        return True

    def may_delete( self, request ):
        return True

    def on_change_pk( self, request, pk, noop, **kwargs ):
        self.set_permissions( 'update', request.user )


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
        # Setup application/request config
        user_id = get_object_id()
        self.request = Request.blank( '/api/v1/' )
        self.request.user = Person( id=user_id, name='dude', email='dude@progressivecompany.com', groups=[ 'g:deliverable1' ] )

        # Instantiate a DocumentCache; it will attach itself to `request.cache`.
        DocumentCache( self.request )

        self.config = testing.setUp( request=self.request )

        self.config.testing_securitypolicy( userid=str( user_id ), permissive=True )

        self.config.set_authorization_policy( ACLAuthorizationPolicy() )

        #self.config.set_authentication_policy( SessionAuthenticationPolicy( 'verysecret' , callback=get_principle_list ) )

        # Setup data
        d = self.data = Struct()

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

    def test_on_change_triggered_once( self ):
        # When updating multiple fields
        pass


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
        dir.save( request=self.request )

        # `update` has been granted
        self.assertTrue( dir.may( self.request, 'update' ) )

        # `bogus` hasn't
        self.assertFalse( dir.may( self.request, 'bogus' ) )

        # `None` and '' are allowed
        self.assertTrue( dir.may( self.request, None ) )
        self.assertTrue( dir.may( self.request, '' ) )

        # `add_file` has been implemented as a method, `may_add_file`
        self.assertTrue( dir.may( self.request, 'add_file' ) )
        self.assertEqual( dir.may_add_file_called, 1 )

        # `validate` could, but shouldn't, raise an exception
        # dir.validate()
        # self.assertEqual( dir.may_add_file_called, 1 )

        # Create a file, save it so give it an `id` and set initial permissions
        file = File( name='todo.txt', directory=dir )
        file.save( self.request )

        # dir.files is still marked as changed, so `may_add_file` should be called when validating
        # `validate` could, but shouldn't, raise an exception
        dir.save( self.request )
        self.assertEqual( dir.may_add_file_called, 1 )

        # the `delete` action doesn't specify a required permission, so `may_delete` won't get called
        self.assertEqual( dir.may_delete_called, 0 )
        dir.delete( self.request )
        self.assertEqual( dir.may_delete_called, 0 )

    def test_update( self ):
        pass

    def test_save( self ):
        pass

    def test_update_privileges( self ):
        pass

    def test_grant( self ):
        pass

    def test_revoke( self ):
        pass

