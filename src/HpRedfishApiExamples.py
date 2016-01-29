# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


"""
Provides examples of using the HP RESTful API on iLO for common use cases.
This is for tutorial/example purposes only.

-----------------------------------------------------------------------------
IMPORTANT!!!
-----------------------------------------------------------------------------
When developing a client for the HP RESTful API, be sure to not code based
upon assumptions that are not guaranteed. Search for, and note any 'NOTE'
comments in this code to read about ways to avoid incorrect assumptions. The
reason avoiding these assumptions is so important is that implementations may
vary across systems and firmware versions, and we want your code to work
consistently.


-----------------------------------------------------------------------------
STARTING ASSUMPTIONS
-----------------------------------------------------------------------------
On URIs:

The HP RESTful API is a "hypermedia API" by design.  This is to avoid building
in restrictive assumptions to the data model that will make it difficult to
adapt to future hardware implementations.  A hypermedia API avoids these
assumptions by making the data model discoverable via links between resources.
A URI should be treated by the client as opaque, and thus should not be
attempted to be understood or deconstructed by the client.  Only specific top
level URIs (any URI in this sample code) may be assumed, and even these may be
absent based upon the implementation (e.g. there might be no /redfish/v1/Systems
collection on something that doesn't have compute nodes.) The other URIs must
be discovered dynamically by following href links. This is because the API
will eventually be implemented on a system that breaks any existing data model
"shape" assumptions we may make now.  In particular, clients should not make
assumptions about the URIs for the resource members of a collection. For
instance, the URI of a collection member will NOT always be
/redfish/v1/.../collection/1, or 2.  On Moonshot a System collection member might
be /redfish/v1/Systems/C1N1. This sounds very complicated, but in reality (as
these examples demonstrate), if you are looking for specific items, the
traversal logic isn't too complicated.


On Resource Model Traversal:

Although the resources in the data model are linked together, because of cross
link references between resources, a client may not assume the resource model
is a tree.  It is a graph instead, so any crawl of the data model should keep
track of visited resources to avoid an infinite traversal loop. A reference to
another resource is any property called "href" no matter where it occurs in a
resource. An external reference to a resource outside the data model is
referred to by a property called "extref".  Any resource referred to by extref
should not be assumed to follow the conventions of the API.
On Resource Versions:
Each resource has a "Type" property with a value of the format Tyepname.x.y.z
where

* x = major version - incrementing this is a breaking change to the schema
* y = minor version - incrementing this is a non-breaking additive change to
      the schema
* z = errata - non-breaking change

Because all resources are versioned and schema also have a version, it is
possible to design rules for "nearest" match (e.g. if you are interacting with
multiple services using a common batch of schema files).  The mechanism is not
prescribed, but a client should be prepared to encounter both older and newer
versions of resource types.


On HTTP POST to create:

When POSTing to create a resource (e.g. create an account or session) the
guarantee is that a successful response includes a "Location" HTTP header
indicating the resource URI of the newly created resource. The POST may also
include a representation of the newly created object in a JSON response body
but may not.  Do not assume the response body, but test it. It may also be an
ExtendedError object.


HTTP REDIRECT:

All clients must correctly handle HTTP redirect. We (or Redfish) may eventually
need to use redirection as a way to alias portions of the data model.


FUTURE:  Asynchronous tasks

In the future some operations may start asynchronous tasks.  In this case, the
client should recognize and handle HTTP 202 if needed and the 'Location' header
will point to a resource with task information and status.


JSON-SCHEMA:

The json-schema available at /redfish/v1/Schemas governs the content of the
resources, keep in mind:

* not every property in the schema is implemented in every implementation.
* some properties are schemed to allow both null and another type like string
  or integer.

Robust client code should check both the existence and type of interesting
properties and fail gracefully if expectations are not met.


GENERAL ADVICE:

Clients should always be prepared for:

* unimplemented properties (e.g. a property doesn't apply in a particular case)
* null values in some cases if the value of a property is not currently known
* HTTP status codes other than '200 OK'. Especially 500 without other
  information.
* URIs are case insensitive
* HTTP header names are case insensitive
* JSON Properties and Enum values are case sensitive
* A client should be tolerant of any set of HTTP headers the service returns
"""


__author__ = 'HP'

import urlparse
import json
import hashlib
from hpsdk.rest.v1 import redfish_client
import logging
import hpsdk

def rest_get(restobj, suburi, request_body):
    """REST GET"""
    restresp = restobj.get(path=suburi)
    status = restresp.status
    headers = dict((x.lower(), y) for x, y in restresp.getheaders())
    thecollection = restresp.dict
    return status, headers, thecollection


def rest_patch(restobj, suburi, request_body):
    """REST PATCH"""
    restresp = restobj.patch(path=suburi, body=request_body)
    status = restresp.status
    headers = dict((x.lower(), y) for x, y in restresp.getheaders())
    thecollection = restresp.dict
    return status, headers, thecollection


def rest_put(restobj, suburi, request_headers, request_body):
    """REST PUT"""
    restresp = restobj.put(path=suburi, body=request_body)
    status = restresp.status
    headers = dict((x.lower(), y) for x, y in restresp.getheaders())
    thecollection = restresp.dict
    return status, headers, thecollection


def rest_post(restobj, suburi, request_headers, request_body):
    """REST POST"""
    restresp = restobj.post(path=suburi, body=request_body)
    status = restresp.status
    headers = dict((x.lower(), y) for x, y in restresp.getheaders())
    thecollection = restresp.dict
    return status, headers, thecollection


def rest_delete(restobj, suburi, request_headers):
    """REST DELETE"""
    restresp = restobj.delete(path=suburi)
    status = restresp.status
    headers = dict((x.lower(), y) for x, y in restresp.getheaders())
    thecollection = restresp.dict
    return status, headers, thecollection


# this is a generator that returns collection members
def collection(restobj, host, collection_uri, request_headers, login_account,
               login_password):
    # get the collection
    status, headers, thecollection = rest_get(restobj, collection_uri,
                                              request_headers)
    # status, headers, thecollection = rest_get(host, collection_uri,
    #                                           request_headers, login_account,
    #                                           login_password)

    while status < 300:
        # verify expected type

        # NOTE:  Because of the Redfish standards effort, we have versioned
        #        many things at 0 in anticipation of them being ratified for
        #        version 1 at some point.  So this code makes the
        #        (unguarranteed) assumption throughout that version 0 and 1
        #        are both legitimate at this point.  Don't write code requiring
        #        version 0 as we will bump to version 1 at some point.

        # hint:  don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        assert (get_type(thecollection) == 'Collection.0' or
                get_type(thecollection) == 'Collection.1')

        # if this collection has inline items, return those
        # NOTE:  Collections are very flexible in how the represent members.
        #        They can be inline in the collection as members of the 'Items'
        #        array, or they may be href links in the links/Members array.
        #        The could actually be both. Typically, iLO implements the
        #        inline (Items) for only when the collection is read only.
        #        We have to render it with the href links when an array
        #        contains PATCHable items because its complex to PATCH
        #        inline collection members. A client may wish to pass in a
        #        boolean flag favoring the href links vs. the Items in case a
        #        collection contains both.

        # iterate members
        for memberuri in thecollection['Members']:
            # for each member return the resource indicated by the member link

            status, headers, member = rest_get(restobj, memberuri['@odata.id'], request_headers)
            # Read up on Python generator functions to understand what this does.
            yield status, headers, member, memberuri['@odata.id']

        # page forward if there are more pages in the collection
        if 'NextPage' in thecollection:
            next_link_uri = collection_uri + '?page=' + str(thecollection['NextPage']['page'])
            status, headers, thecollection = rest_get(restobj, next_link_uri, request_headers)

        # else we are finished iterating the collection
        else:
            break


# return the type of an object (down to the major version, skipping minor, and errata)
def get_type(obj):
    if obj['@odata.type'].endswith('Collection'):
        return 'Collection.1'
    else:
        typever = obj['@odata.type']
        typesplit = typever.split('.')
        return typesplit[0][1:] + '.' + typesplit[1]


# checks HTTP response headers for specified operation (e.g. 'GET' or 'PATCH')
def operation_allowed(headers_dict, operation):
    if 'allow' in headers_dict:
        if headers_dict['allow'].find(operation) != -1:
            return True
    return False



# Message registry support
MESSAGE_REGISTRIES = {}

# Build a list of decoded messages from the extended_error using the message registries
# An ExtendedError JSON object is a response from the with its own schema.  This function knows
# how to parse the ExtendedError object and, using any loaded message registries, render an array of
# plain language strings that represent the response.
def render_extended_info_message_list(extended_info):
    messages = []
    if (isinstance(extended_info, dict) and ('error' in extended_info) and
            ('code' in extended_info['error']) and
            ('@Message.ExtendedInfo' in extended_info['error'])):
        for msg in extended_info['error']['@Message.ExtendedInfo']:
            MessageID = msg['MessageId']
            x = MessageID.split('.')
            registry = x[0]
            msgkey = x[-1]

            # if the correct message registry is loaded, do string resolution
            if registry in MESSAGE_REGISTRIES:
                if (registry in MESSAGE_REGISTRIES and msgkey in
                        MESSAGE_REGISTRIES[registry]['Messages']):
                    msg_dict = MESSAGE_REGISTRIES[registry]['Messages'][msgkey]
                    msg_str = MessageID + ':  ' + msg_dict['Message']

                    for argn in range(0, msg_dict['NumberOfArgs']):
                        subst = '%' + str(argn+1)
                        msg_str = msg_str.replace(subst, str(msg['MessageArgs'][argn]))

                    if 'Resolution' in msg_dict and msg_dict['Resolution'] != 'None':
                        msg_str += '  ' + msg_dict['Resolution']

                    messages.append(msg_str)
            else: # no message registry, simply return the msg object in string form
                messages.append('No Message Registry Info:  '+ str(msg))

    return messages

# Print a list of decoded messages from the extended_error using the message registries
def print_extended_info(extended_info):
    messages = render_extended_info_message_list(extended_info)
    msgcnt = 0
    for msg in messages:
        print '\t' + msg
        msgcnt += 1
    if msgcnt == 0: # add a spacer
        print


def create_object(host, login_account, login_password):
    restobj = redfish_client(base_url=host,
                             username=login_account, password=login_password,
                             default_prefix='/redfish/v1')
    restobj.login(auth="session")
    return restobj


def get_headers(headers, propertyname):
    for header in headers:
        if header[0].lower() == propertyname.lower():
            return header[0]
        return None


# noinspection PyPep8Naming
def ex1_change_bios_setting(restobj, host, bios_property, value, login_account,
                            login_password, bios_password):
    print 'EXAMPLE 1:  Change a BIOS setting'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj, host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):
        # verify expected type
        # hint:  don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')
        # find the BIOS URI
        if ('links' not in system['Oem']['Hp'] or 'BIOS' not in
                system['Oem']['Hp']['links']):
            print ('\tBIOS Settings resource or feature is not supported on '
                   'this system')
            return
        bios_uri = system['Oem']['Hp']['links']['BIOS']['href']

        # get the BIOS object
        status, headers, bios_settings = rest_get(restobj, bios_uri, None)

        # check to make sure the bios_property is supported
        # if not, its OK to PATCH it but it will generate an error if not
        # implemented and waste everyone's time
        if bios_property not in bios_settings:
            # not supported on this platform
            print ('\tBIOS Property "' + bios_property + '" is not supported '
                   'on this system')
            return

        # if this BIOS resource doesn't support PATCH, go get the Settings,
        # which should
        if not operation_allowed(headers, 'PATCH'):   # this is GET-only
            bios_uri = bios_settings['links']['Settings']['href']
            status, headers, bios_settings = rest_get(restobj, bios_uri, None)
            #assert operation_allowed(headers, 'PATCH')   # this allows PATCH

        # we don't need to PATCH back everything, just the one bios_property we
        # want to change
        new_bios_settings = dict()
        new_bios_settings[bios_property] = value
        request_headers = dict()
        if bios_password:
            bios_password_hash = hashlib.sha256(
                bios_password.encode()).hexdigest().upper()
            request_headers['X-HPRESTFULAPI-AuthToken'] = bios_password_hash

        # perform the patch
        print 'PATCH ' + json.dumps(new_bios_settings) + ' to ' + bios_uri
        status, headers, response = rest_patch(restobj, bios_uri,
                                               new_bios_settings)
        print 'PATCH response = ' + str(status)
        print_extended_info(response)
        #assert status < 300

        # point made...quit
        break


# noinspection PyPep8Naming
def ex2_reset_server(restobj, host, login_account, login_password):

    print 'EXAMPLE 2:  Reset a server'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj,
                                                         host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')

        # verify it supports POST
        # assert(operation_allowed(headers, 'POST'))

        action = dict()
        action['Action'] = 'Reset'
        action['ResetType'] = 'ForceRestart'

        # perform the POST action
        print 'POST ' + json.dumps(action) + ' to ' + memberuri
        status, headers, response = rest_post(restobj, memberuri, None, action)
        print 'POST response = ' + str(status)
        print_extended_info(response)

        # point made...quit
        break


# noinspection PyPep8Naming
def ex3_enable_secure_boot(restobj, host, secure_boot_enable, login_account,
                           login_password):

    print 'EXAMPLE 3:  Enable UEFI Secure Boot'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj,
                                                         host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):
        # find the BIOS URI
        if ('Links' not in system['Oem']['Hp'] or 'SecureBoot' not in
                system['Oem']['Hp']['Links']):
            print ('\t"SecureBoot" resource or feature is not supported on '
                   'this system')
            return

        secure_boot_uri = system['Oem']['Hp']['Links']['SecureBoot']['@odata.id']

        # get the Secure Boot object
        status, headers, secure_boot_settings = rest_get(restobj,
                                                         secure_boot_uri,
                                                         None)

        # Settings fail and the operations allowed doesn't check
        # the headers right.

        # if the BIOS doesn't support PATCH, go get the Settings, which should
        if not operation_allowed(headers, 'PATCH'):   # this is GET-only
            secure_boot_uri = secure_boot_settings['links']['Settings']['href']
            status, headers, boot_settings = rest_get(restobj, host,
                                                      secure_boot_uri)
            assert operation_allowed(headers, 'PATCH')  # this allows PATCH

        # we don't need to PATCH back everything, just the one property we want
        # to change
        new_secure_boot_settings = dict()
        new_secure_boot_settings['SecureBootEnable'] = secure_boot_enable

        # perform the patch
        print ('PATCH ' + json.dumps(new_secure_boot_settings) + ' to ' +
               secure_boot_uri)
        status, headers, response = rest_patch(restobj, secure_boot_uri,
                                               new_secure_boot_settings)
        print 'PATCH response = ' + str(status)
        print_extended_info(response)

        # point made...quit
        break


# noinspection PyPep8Naming
def ex4_bios_revert_default(restobj, host, login_account, login_password,
                            default_overrides=None):

    if not default_overrides:
        default_overrides = {}
    print 'EXAMPLE 4:  Revert BIOS Settings to default'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj, host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):

        # find the BIOS URI
        if ('Links' not in system['Oem']['Hp'] or 'BIOS' not in
                system['Oem']['Hp']['Links']):
            print ('\tBIOS Settings resource or feature is not supported on '
                   'this system')
            return
        bios_uri = system['Oem']['Hp']['Links']['BIOS']['@odata.id']

        # get the BIOS object
        status, headers, bios_settings = rest_get(restobj, bios_uri, None)

        # if the BIOS doesn't support PUT, go get the Settings, which should
        if not operation_allowed(headers, 'PUT'):   # this is GET-only
            if 'Settings' not in bios_settings['links']:
                print 'No BIOS settings resources allow PUT'
                return
            bios_uri = bios_settings['links']['Settings']['href']
            status, headers, bios_settings = rest_get(restobj, bios_uri, None)
            # assert(operation_allowed(headers, 'PUT'))   # this allows PUT

        # we don't need to PUT back everything, just the one property
        # we want to change
        new_bios_settings = dict()
        new_bios_settings['BaseConfig'] = 'default'
        # preserve the Type property from the existing BIOS settings to
        # avoid an error
        new_bios_settings['Type'] = bios_settings['Type']
        # add in any caller-supplied override properties
        for override in default_overrides:
            new_bios_settings[override] = default_overrides[override]

        # perform the patch
        print 'PUT ' + json.dumps(new_bios_settings) + ' to ' + bios_uri
        status, headers, response = rest_put(restobj, bios_uri, None,
                                             new_bios_settings)
        print 'PUT response = ' + str(status)
        print_extended_info(response)
        assert status < 300

        # point made...quit
        break


# noinspection PyPep8Naming
def ex5_change_boot_order(restobj, host, login_account, login_password,
                          bios_password):

    print 'EXAMPLE 5:  Change Boot Order (UEFI)'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj,
                                                         host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):

        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')

        # find the BIOS URI
        if ('Links' not in system['Oem']['Hp'] or 'BIOS' not in
                system['Oem']['Hp']['Links']):
            print ('\tBIOS Settings resource or feature is not supported on '
                   'this system')
            return
        bios_uri = system['Oem']['Hp']['Links']['BIOS']['@odata.id']

        # get the BIOS object
        status, headers, bios_settings = rest_get(restobj, bios_uri, None)

        # get the BOOT object
        if 'Boot' not in bios_settings['links']:
            print ('\t"links" section in Bios settings does not have a Boot '
                   'order resource')
            return
        boot_uri = bios_settings['links']['Boot']['href']
        status, headers, boot_settings = rest_get(restobj, boot_uri, None)

        # if the BIOS doesn't support PATCH, go get the Settings, which should
        if not operation_allowed(headers, 'PATCH'):   # this is GET-only
            boot_uri = boot_settings['links']['Settings']['href']
            status, headers, boot_settings = rest_get(restobj, boot_uri, None)
            # assert(operation_allowed(headers, 'PATCH'))   # this allows PATCH

        # we don't need to PATCH back everything,
        # just the one property we want to change
        new_boot_settings = dict()
        new_boot_settings['PersistentBootConfigOrder'] = boot_settings[
            'PersistentBootConfigOrder']

        # TODO - rearrange new_boot_settings['PersistentBootConfigOrder'] with
        #        the desired order

        # supply the BIOS setup login_password
        request_headers = dict()
        if bios_password:
            bios_password_hash = hashlib.sha256(
                bios_password.encode()).hexdigest().upper()
            request_headers['X-HPRESTFULAPI-AuthToken'] = bios_password_hash

        # perform the patch
        print 'PATCH ' + json.dumps(new_boot_settings) + ' to ' + boot_uri
        status, headers, response = rest_patch(restobj, boot_uri,
                                               new_boot_settings)
        print 'PATCH response = ' + str(status)
        print_extended_info(response)
        assert status < 300

        # point made...quit
        break


# noinspection PyPep8Naming
def ex6_change_temporary_boot_order(restobj, host, boottarget, login_account,
                                    login_password):

    print ('EXAMPLE 6:  Change temporary boot order (one time boot or '
           'temporary override)')

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj,
                                                         host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):

        # verify it supports PATCH
        assert operation_allowed(headers, 'PATCH')

        # verify the requested boot target is supported
        #  no BootSourceOverrideSupported in RF
        #  if boottarget in system['Boot']['BootSourceOverrideSupported']:

        #      # build a PATCH payload to change to the requested boot target
        #      boot = dict()
        #      boot['Boot'] = dict()
        #      boot['Boot']['BootSourceOverrideTarget'] = boottarget

        #      # perform the POST action
        #      print('PATCH ' + json.dumps(boot) + ' to ' + memberuri)
        #      status, headers, response = rest_patch(host, memberuri, None, boot,
        #          iLO_loginname, iLO_password)
        #      print('PATCH response = ' + str(status))
        #      print_extended_info(response)

        #  else:  # target not in supported list
        #      print ('\tBootSourceOverrideTarget value "' + boottarget + '" is '
        #      'not supported. Valid values are:')
        #      for tgt in system['Boot']['BootSourceOverrideSupported']:
        #          print '\t\t' + tgt

        # build a PATCH payload to change to the requested boot target
        boot = dict()
        boot['Boot'] = dict()
        boot['Boot']['BootSourceOverrideTarget'] = boottarget

        # perform the POST action
        print 'PATCH ' + json.dumps(boot) + ' to ' + memberuri
        status, headers, response = rest_patch(restobj, memberuri, boot)
        print 'PATCH response = ' + str(status)
        print_extended_info(response)

        # point made...quit
        break


# noinspection PyPep8Naming
def ex7_find_ilo_mac_address(restobj, host, login_account, login_password):

    print "EXAMPLE 7:  Find iLO's MAC Addresses"

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj,
                                                          host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        #print manager

        # for each system in the systems collection at /redfish/v1/Systems
        for status, headers, nic, memberuri in collection(
                restobj, host, manager['EthernetInterfaces'][
                    '@odata.id'], None,
                login_account, login_password):

            # verify expected type
            # hint:  Don't limit to version 0 here as we will rev to 1.0 at
            #        some point hopefully with minimal changes
            #assert (get_type(nic) == 'EthernetInterface.0' or
            #        get_type(nic) == 'EthernetInterface.1')
            if 'MACAddress' not in nic:
                print '\tNIC resource does not contain "MacAddress" property'
            else:
                print ('\t' + nic['Name'] + ' = ' +
                       nic['MACAddress'] + '\t(' + nic['Status']['State'] +
                       ')')


# noinspection PyPep8Naming
def ex8_add_ilo_user_account(restobj, host, login_account, login_password,
                             new_ilo_loginname, new_ilo_username,
                             new_ilo_password, irc=False, cfg=False,
                             virtual_media=False, usercfg=False, vpr=False):

    print 'EXAMPLE 8:  Create an iLO User Account'

    # get the URI of the Accounts collection (not standardized)
    status, headers, obj = rest_get(restobj, '/redfish/v1/AccountService', None)
    assert status == 200

    account_collection = obj['Accounts']['@odata.id']

    # build up a new account object to create
    # iLO has two user account properties:
    #     Login name = the string used as the user identity to
    #                  log in - we use this for 'UserName'
    #     User name = the friendly (or full) name of the user
    #                 Potentially easy to reverse, so be careful - use the
    #                 iLO account login name as 'UserName' in the API
    user = {
        'UserName': new_ilo_loginname,
        'Password': new_ilo_password,
        'Oem': {}
    }

    # Supply the full name as LoginName
    user['Oem']['Hp'] = {}
    # again this is tricky:  LoginName gets the friendly user name
    user['Oem']['Hp']['LoginName'] = new_ilo_username

    # plug in the requested privileges, by default you get LoginPriv
    # and nothing else
    user['Oem']['Hp']['Privileges'] = {}
    user['Oem']['Hp']['Privileges']['RemoteConsolePriv'] = irc
    user['Oem']['Hp']['Privileges']['iLOConfigPriv'] = cfg
    user['Oem']['Hp']['Privileges']['VirtualMediaPriv'] = virtual_media
    user['Oem']['Hp']['Privileges']['UserConfigPriv'] = usercfg
    user['Oem']['Hp']['Privileges']['VirtualPowerAndResetPriv'] = vpr

    # create the account
    print 'POST ' + json.dumps(user) + ' to ' + account_collection
    status, headers, response = rest_post(restobj, account_collection,
                                          None, user)
    print 'POST response = ' + str(status)
    print_extended_info(response)

    if status == 201:
        # this is the new account URI
        # HTTP headers are not case sensitive
        new_account_uri = headers['location']
        print 'Account ' + new_account_uri + ' created'

        # get the new account resource
        # it is possible that a future version of iLO will
        # simply return the new account resource in the create
        # response
        status, headers, acct = rest_get(restobj,
                                         urlparse.urlparse(
                                             new_account_uri).path,
                                         None)
        assert status == 200
        # print('Account info:  ' + json.dumps(acct, indent=4))

        # demonstration of how to remove the account using the Location header
        # status, headers, response = rest_delete(
        #     host, urlparse(new_account_uri).path, None, login_account,
        #     login_password)
        # assert(status == 200)
        # print('Account ' + new_account_uri + ' removed')


# noinspection PyPep8Naming
def ex9_modify_ilo_user_account(restobj, host, login_account, login_password,
                                ilo_login_name_to_modify, new_loginname=None,
                                new_username=None, new_password=None, irc=None,
                                cfg=None, virtual_media=None, usercfg=None,
                                vpr=None):

    print 'EXAMPLE 9:  Modify an iLO user account'

    # get the URI of the Accounts collection (not standardized)
    status, headers, obj = rest_get(restobj, '/redfish/v1/AccountService', None)
    assert status == 200
    account_collection = obj['Accounts']['@odata.id']

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, account, memberuri in collection(restobj, host,
                                                          account_collection,
                                                          None, login_account,
                                                          login_password):
        # iLO has two user account properties:
        #     Login name = the string used as the user identity to log in - we
        #                  use this for 'UserName'
        #     User name = the friendly (or full) name of the user
        #                 Potentially easy to reverse, so be careful - use the
        #                 iLO account login name as 'UserName' in the API
        if account['UserName'] == ilo_login_name_to_modify:
            # Cannot read/modify/write same object because iLO will reject
            # non-PATCHable properties
            # i.e. if I just change 'login_password' and PATCH back I get an
            #      error identifying 'Description' as non-PATCHable

            # this resource handler is a little picky about passing in empty
            # objects, so only add what we need by assembling what's actually
            # used.
            mod_user = {}
            mod_user_oemhp = {}
            mod_user_oemhp_privs = {}

            # if new loginname or password specified
            if new_password:
                mod_user['Password'] = new_password
            if new_loginname:
                mod_user['UserName'] = new_loginname

            # if different username specified
            if new_username:
                mod_user_oemhp['LoginName'] = new_username

            # if different privileges were requested (None = no change)
            if irc != None:
                mod_user_oemhp_privs['RemoteConsolePriv'] = irc
            if virtual_media != None:
                mod_user_oemhp_privs['VirtualMediaPriv'] = virtual_media
            if cfg != None:
                mod_user_oemhp_privs['iLOConfigPriv'] = cfg
            if usercfg != None:
                mod_user_oemhp_privs['UserConfigPriv'] = usercfg
            if vpr != None:
                mod_user_oemhp_privs['VirtualPowerAndResetPriv'] = vpr

            # component assembly
            if len(mod_user_oemhp_privs):
                mod_user_oemhp['Privileges'] = mod_user_oemhp_privs
            if len(mod_user_oemhp):
                mod_user['Oem'] = {'Hp': mod_user_oemhp}

            # patch the account
            status, headers, response = rest_patch(restobj,
                                                   memberuri, mod_user)
            # Warning, if you don't change anything,
            # you will get an HTTP 400 back
            # assert(status == 200)
            if status == 200:
                print 'Account ' + memberuri + ' account modified'
            else:
                print ('Account ' + memberuri + ' account not modified. '
                       'HTTP Status = ' + str(status))
            print_extended_info(response)
            return

    print 'Account not found'


# noinspection PyPep8Naming
def ex10_remove_ilo_account(restobj, host, login_account, login_password,
                            ilo_loginname_to_remove):

    print 'EXAMPLE 10:  Remove an iLO account'

    # get the URI of the Accounts collection (not standardized)
    status, headers, obj = rest_get(restobj, '/redfish/v1/AccountService', None)
    assert status == 200
    account_collection = obj['Accounts']['@odata.id']

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, account, memberuri in collection(restobj, host,
                                                          account_collection,
                                                          None, login_account,
                                                          login_password):
        # iLO has two user account properties:
        #     Login name = the string used as the user identity to log in - we
        #                  use this for 'UserName'
        #     User name = the friendly (or full) name of the user
        #                 Potentially easy to reverse, so be careful - use the
        #                 iLO account login name as 'UserName' in the API
        if account['UserName'] == ilo_loginname_to_remove:

            # demonstration of how to remove the account
            status, headers, response = rest_delete(restobj, memberuri, None)
            print_extended_info(response)
            assert status == 200
            print 'Account ' + memberuri + ' removed'
            return

    print 'Account not found'


# noinspection PyPep8Naming
def ex11_dump_ilo_nic(restobj, host, login_account, login_password):

    print 'EXAMPLE 11:  Get iLO NIC state'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj,
                                                          host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):

        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        # for each system in the systems collection at /redfish/v1/Systems
        for status, headers, nic, memberuri in collection(
                restobj, host, manager['EthernetInterfaces']['@odata.id'], None,
                login_account, login_password):

            # verify expected type
            # hint:  Don't limit to version 0 here as we will rev to 1.0 at
            #        some point hopefully with minimal changes
            #assert (get_type(nic) == 'EthernetNetworkInterface.0' or
            #        get_type(nic) == 'EthernetNetworkInterface.1')

            if nic['Status']['State'] == 'Enabled':
                print '\t' + nic['Name']
                if 'MacAddress' not in nic:
                    print ('\tNo MacAddress information available (no '
                           '"MacAddress" property in NIC resource)')
                else:
                    print '\tMAC: ' + str(nic['MacAddress'])
                print '\tSpeed: ' + str(nic['SpeedMbps'])
                #No Autosense in RF
                #print '\tAutosense:  ' + str(nic['Autosense'])
                print '\tFull Duplex:  ' + str(nic['FullDuplex'])
                if 'FQDN' not in nic:
                    print '\tNo FQDN information available'
                else:
                    print '\tFQDN:  ' + str(nic['FQDN'])
                for addr in nic['IPv4Addresses']:
                    print ('\tIPv4 Address:  ' + addr['Address'] + ' from ' +
                           addr['AddressOrigin'])
                if 'IPv6Addresses' not in nic:
                    print '\tIPv6Addresses information not available'
                else:
                    for addr in nic['IPv6Addresses']:
                        print ('\tIPv6 Address:  ' + addr['Address'] + ' from '
                               + addr['AddressOrigin'])
                # print(json.dumps(nic, indent=4))


def ex12_sessions(restobj, host, login_account, login_password):

    print 'EXAMPLE 12:  Create/Use/Delete a user session'

    # build up a new session object to create
    # iLO has two user account properties:
    #     Login name = the string used as the user identity to log in - we use
    #                  this for 'UserName'
    #     User name = the friendly (or full) name of the user
    #                 Potentially easy to reverse, so be careful - use the iLO
    #                 account login name as 'UserName' in the API
    new_session = {"UserName": login_account, "Password": login_password}

    # create the session
    print 'POST ' + json.dumps(new_session) + ' to /redfish/v1/Sessions'
    status, headers, response = rest_post(restobj,
                                          '/redfish/v1/Sessions',
                                          None, new_session)
    print 'POST response = ' + str(status) + ', ' + str(response)
    assert status == 201

    # this is the new account URI
    # iLO returns lower case header names, be careful of casing.
    # HTTP says headers are case insensitive.
    session_uri = headers['location']
    session_uri = urlparse.urlparse(session_uri).path
    print '\tSession ' + session_uri + ' created'
    x_auth_token = headers['x-auth-token']

    # get the new session resource
    # This could be returned on the create operation instead of the
    # ExtendedError created result
    # Instead of login_account/login_password here, use the newly supplied x
    # auth_token and the low level form of rest_op
    request_headers = {'X-Auth-Token': x_auth_token}
    status, headers, session = rest_get(restobj, session_uri, request_headers)
    assert status == 200
    # this flag is used for "whoami"
    # assert(session['Oem']['Hp']['MySession'] == True)
    # print('Session info:  ' + json.dumps(session, indent=4))
    print ('\tLogged in from IP ' + session['Oem']['Hp']['UserIP'] + ' using '
           'session token ' + x_auth_token)

    # demonstration of how to log out
    status, headers, response = rest_delete(restobj, session_uri, None)
    assert status == 200
    print '\tSession ' + session_uri + ' logged out'


# noinspection PyPep8Naming
def ex13_set_uid_light(restobj, host, uid, login_account, login_password):

    print 'EXAMPLE 13:  Set UID Light on or off'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj, host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')

        # verify it supports POST
        #assert operation_allowed(headers, 'PATCH')  # This needs to be changed

        uid_state = dict()
        if uid:
            uid_state['IndicatorLED'] = 'Lit'
        else:
            uid_state['IndicatorLED'] = 'Off'

        # perform the POST action
        print 'PATCH ' + json.dumps(uid_state) + ' to ' + memberuri
        status, headers, response = rest_patch(restobj, memberuri, uid_state)
        print 'PATCH response = ' + str(status)
        print_extended_info(response)
        assert status < 300

        # point made...quit
        break


# noinspection PyPep8Naming
def ex14_computer_details(restobj, host, login_account, login_password):

    print 'EXAMPLE 14:  Dump host computer details'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj, host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):

        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')

        # wrap these values in str() because some that are normally strings
        # can also be null (None in Python)
        print '\tManufacturer:  ' + str(system['Manufacturer'])
        print '\tModel:  ' + str(system['Model'])
        print '\tSerial Number:  ' + str(system['SerialNumber'])
        if 'VirtualSerialNumber' in system:
            print ('\tVirtual Serial Number:  ' +
                   str(system['VirtualSerialNumber']))
        else:
            print ('\tVirtual Serial Number information not available on '
                   'system resource')
        print '\tUUID:  ' + str(system['UUID'])
        if 'VirtualUUID' in system['Oem']['Hp']:
            print '\tVirtualUUID:  ' + str(system['Oem']['Hp']['VirtualUUID'])
        else:
            print '\tVirtualUUID not available system resource'
        if 'AssetTag' in system:
            print '\tAsset Tag:  ' + system['AssetTag']
        else:
            print '\tNo Asset Tag information on system resource'
        #system['Bios']['Current']['VersionString'] is not available in RF
        print '\tBIOS Version: ' + system['Oem']['Hp']['Bios']['Current']['VersionString']
        print ('\tMemory:  ' + str(system['MemorySummary']['TotalSystemMemoryGiB']) +
               ' GB')
        print ('\tProcessors:  ' + str(system['ProcessorSummary']['Count']) + ' x ' +
               str(system['ProcessorSummary']['Model']))
        if 'Status' not in system or 'Health' not in system['Status']:
            print ('\tStatus/Health information not available in system '
                   'resource')
        else:
            print '\tHealth:  ' + str(system['Status']['Health'])

        if 'HostCorrelation' in system:
            if 'HostFQDN' in system['HostCorrelation']:
                print '\tHost FQDN:  ' + system['HostCorrelation']['HostFQDN']
            if 'HostMACAddress' in system['HostCorrelation']:
                for mac in system['HostCorrelation']['HostMACAddress']:
                    print '\tHost MAC Address:  ' + str(mac)
            if 'HostName' in system['HostCorrelation']:
                print '\tHost Name:  ' + system['HostCorrelation']['HostName']
            if 'IPAddress' in system['HostCorrelation']:
                for ip_address in system['HostCorrelation']['IPAddress']:
                    print '\tHost IP Address:  ' + str(ip_address)

        # point made...quit
        break


# Mount an ISO to virtual media and optionally specify whether it should be the
# boot target for the next server reset.
# if iso_url is left out, it unmounts
# if boot_on_next_server_reset is left out the option is not set one way or
# the other noinspection PyPep8Naming
def ex15_mount_virtual_media_iso(restobj, host, login_account, login_password,
                                 iso_url=None, boot_on_next_server_reset=None):

    print 'EXAMPLE 15:  Mount iLO Virtual Media DVD ISO from URL'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        if 'VirtualMedia' not in manager:
            print '\tVirtualMedia not available in manager'
            continue

        # for each system in the systems collection at /redfish/v1/Systems
        for status, headers, virtual_media, memberuri in collection(
                restobj, host, manager['VirtualMedia']['@odata.id'], None,
                login_account, login_password):

            # verify expected type
            # hint:  Don't limit to version 0 here as we will rev to 1.0 at
            #        some point hopefully with minimal changes
            #assert (get_type(virtual_media) == 'VirtualMedia.0' or
            #        get_type(virtual_media) == 'VirtualMedia.1')

            if 'DVD' in virtual_media['MediaTypes']:
                mount = {'Image': iso_url}
                # only add this if we are mounting and user specified
                # something to set
                if (iso_url is not None and
                        boot_on_next_server_reset is not None):
                    mount['Oem'] = {
                        'Hp': {
                            'BootOnNextServerReset': boot_on_next_server_reset
                        }}
                # perform the patch
                print 'PATCH ' + json.dumps(mount) + ' to ' + memberuri
                status, headers, response = rest_patch(restobj,
                                                       memberuri, mount)
                print 'PATCH response = ' + str(status)
                print_extended_info(response)
                if status == 400:
                    # this will respond with 400 if the virtual_media state is
                    # already in this state  assert(status < 300)
                    pass
                else:
                    assert status < 300

                # finished
                break
        break


# noinspection PyPep8Naming
def ex16_set_server_asset_tag(restobj, host, login_account, login_password,
                              asset_tag):

    print 'EXAMPLE 16:  Set Computer Asset Tag'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj, host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):

        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')

        obj = {'AssetTag': asset_tag}

        # perform the patch
        print 'PATCH ' + json.dumps(obj) + ' to ' + memberuri
        status, headers, response = rest_patch(restobj, memberuri, obj)
        print 'PATCH response = ' + str(status)
        print_extended_info(response)
        # Skip this assertion
        # assert(status < 300)

        # point made...quit
        break


# noinspection PyPep8Naming
def ex17_reset_ilo(restobj, host, login_account, login_password):

    print 'EXAMPLE 17:  Reset iLO'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')
        action = {'Action': 'Reset'}

        # perform the POST
        print 'POST ' + json.dumps(action) + ' to ' + memberuri
        status, headers, response = rest_post(restobj,
                                              memberuri, None, action)
        print_extended_info(response)
        assert status == 200

        break


# noinspection PyPep8Naming
def ex18_get_ilo_nic(restobj, host, login_account, login_password,
                     get_active=True):

    print "EXAMPLE 18:  Get iLO's NIC configuration"

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')
        # for each system in the systems collection at /redfish/v1/Systems
        for status, headers, nic, memberuri in collection(
                restobj, host, manager['EthernetInterfaces']['@odata.id'], None,
                login_account, login_password):

            # verify expected type
            # hint:  Don't limit to version 0 here as we will rev to 1.0 at
            #        some point hopefully with minimal changes
            #assert (get_type(nic) == 'EthernetNetworkInterface.0' or
            #        get_type(nic) == 'EthernetNetworkInterface.1')

            if get_active and nic['Status']['State'] == 'Enabled':
                # this is the active NIC
                return memberuri, nic
            elif get_active == False and nic['Status']['State'] == 'Disabled':
                # this is the inactive NIC
                return memberuri, nic


def ex19_set_active_ilo_nic(restobj, host, login_account, login_password,
                            shared_nic=False):

    print "EXAMPLE 19:  Set the active iLO NIC"

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        selected_nic_uri = None

        # for each system in the systems collection at /redfish/v1/Systems
        for status, headers, nic, memberuri in collection(
                restobj, host, manager['EthernetInterfaces']['@odata.id'], None,
                login_account, login_password):

            # verify expected type
            # hint:  Don't limit to version 0 here as we will rev to 1.0 at
            #        some point hopefully with minimal changes
            #assert (get_type(nic) == 'EthernetNetworkInterface.0' or
            #        get_type(nic) == 'EthernetNetworkInterface.1')

            # this is a little complex but we are just looking for the
            # dedicated vs. shared NIC without assuming the order or URIs
            # in the NICs collection.
            try:
                if (nic['Oem']['Hp']['SupportsFlexibleLOM'] == True and
                        shared_nic == True):
                    # this is the shared NIC
                    selected_nic_uri = memberuri
                    break
            except KeyError:
                pass
            try:
                if (nic['Oem']['Hp']['SupportsLOM'] == True and
                        shared_nic == True):
                    # this is the shared NIC
                    selected_nic_uri = memberuri
                    break
            except KeyError:
                pass

            if not shared_nic:
                selected_nic_uri = memberuri
                break
            elif not selected_nic_uri:
                print '\tShared NIC is not supported'
                break

        # we should have found the desired NIC
        if selected_nic_uri:

            # build the request header
            request = {'Oem': {'Hp': {'NICEnabled': True}}}

            # perform the PATCH
            print 'PATCH ' + json.dumps(request) + ' to ' + memberuri
            status, headers, response = rest_patch(restobj, selected_nic_uri,
                                                   request)
            print_extended_info(response)


def ex20_dump_iml(restobj, host, login_account, login_password):

    print 'EXAMPLE 20:  Dump Integrated Management Log'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj, host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')

        if 'LogServices' not in system['Links']:
            print '\tLogs not available on system resource'
            return
        logsuri = system['LogServices']['@odata.id']
        for status, headers, log, memberuri in collection(restobj, host,
                                                          logsuri, None,
                                                          login_account,
                                                          login_password):
            # assert(get_type(log) == 'LogService.0' or
            #        get_type(log) == 'LogService.1')

            entries_collection_array = log['Links']['Entries']
            for entries_collection in entries_collection_array:
                entries_collection_uri = entries_collection['@odata.id']
                for status, headers, log_entry, log_entry_uri in collection(
                        restobj, host, entries_collection_uri, None,
                        login_account, login_password):
                    print (log_entry['Severity'] + ': Class ' +
                           str(log_entry['Oem']['Hp']['Class']) + ' / Code ' +
                           str(log_entry['Oem']['Hp']['Code']) + ':\t' +
                           log_entry['Message'])
        # example only - don't iterate all systems
        break


def ex21_dump_ilo_event_log(restobj, host, login_account, login_password):

    print 'EXAMPLE 21:  Dump iLO Event Log'

    # for each manager in the managers collection at /redfish/v1/Managers
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        if 'LogServices' not in manager['Links']:
            print '\tLogs not available on manager resource'
            return
        logsuri = manager['LogServices']['@odata.id']
        for status, headers, log, memberuri in collection(restobj, host,
                                                          logsuri, None,
                                                          login_account,
                                                          login_password):

            #assert (get_type(log) == 'LogService.0' or
            #        get_type(log) == 'LogService.1')

            entries_collection_array = log['Links']['Entries']
            for entries_collection in entries_collection_array:

                entries_collection_uri = entries_collection['@odata.id']
                for status, headers, log_entry, log_entry_uri in collection(
                        restobj, host, entries_collection_uri, None,
                        login_account, login_password):

                    print log_entry['Message']
                    # status, headers, response = rest_get(host, iml, None,
                    #                                      login_account,
                    #                                      login_password)

        # example only - don't iterate all managers
        break


def ex22_clear_iml(restobj, host, login_account, login_password):

    print 'EXAMPLE 22:  Clear Integrated Management Log'

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, system, memberuri in collection(restobj, host,
                                                         '/redfish/v1/Systems',
                                                         None, login_account,
                                                         login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(system) == 'ComputerSystem.0' or
        #        get_type(system) == 'ComputerSystem.1')

        if 'LogServices' not in system['Links']:
            print '\tLogs not available on system resource'
            return
        logsuri = system['LogServices']['@odata.id']
        for status, headers, log, memberuri in collection(restobj, host,
                                                          logsuri, None,
                                                          login_account,
                                                          login_password):
            #assert (get_type(log) == 'LogService.0' or
            #        get_type(log) == 'LogService.1')

            action = {'Action': 'ClearLog'}

            # perform the POST
            print 'POST ' + json.dumps(action) + ' to ' + memberuri
            status, headers, response = rest_post(restobj, memberuri, None,
                                                  action)
            print_extended_info(response)
            assert status == 200

            break

        # example only - don't iterate all systems
        break


def ex23_clear_ilo_event_log(restobj, host, login_account, login_password):

    print 'EXAMPLE 23:  Clear iLO Event Log'

    # for each manager in the managers collection at /redfish/v1/Managers
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        if 'LogServices' not in manager['Links']:
            print '\tLogs not available on manager resource'
            return
        logsuri = manager['LogServices']['@odata.id']
        for status, headers, log, memberuri in collection(restobj, host,
                                                          logsuri, None,
                                                          login_account,
                                                          login_password):

            #assert (get_type(log) == 'LogService.0' or
            #        get_type(log) == 'LogService.1')

            action = {'Action': 'ClearLog'}

            # perform the POST
            print 'POST ' + json.dumps(action) + ' to ' + memberuri
            status, headers, response = rest_post(restobj, memberuri, None,
                                                  action)
            print_extended_info(response)
            assert status == 200

            break

        # example only - don't iterate all managers
        break


def ex24_configure_snmp(restobj, host, login_account, login_password,
                        snmp_mode, snmp_alerts):

    print "EXAMPLE 24:  Configure iLO SNMP Settings"

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):

        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        # get the Network Service resource
        status, headers, network_protocol = rest_get(
            restobj, manager['NetworkProtocol']['@odata.id'], None)
        #assert (get_type(network_protocol) == 'ManagerNetworkService.0' or
        #        get_type(network_protocol) == 'ManagerNetworkService.1')

        # get the SNMP resource
        if 'SNMPService' not in network_protocol:
            print '\tSNMPService not found in manager network service links'
            continue

        status, headers, snmp_service = rest_get(
            restobj, network_protocol['SNMPService']['@odata.id'], None)
        #assert (get_type(snmp_service) == 'SnmpService.0' or
        #        get_type(snmp_service) == 'SnmpService.1')

        config = {'Mode': snmp_mode, 'AlertsEnabled': snmp_alerts}

        # perform the POST
        print ('PATCH ' + json.dumps(config) + ' to ' +
               network_protocol['SNMPService']['@odata.id'])
        status, headers, response = rest_patch(
            restobj, network_protocol['SNMPService']['@odata.id'], config)
        print_extended_info(response)
        assert status == 200


def ex25_get_schema(restobj, host, login_account, login_password,
                    schema_prefix):

    # This could be augmented to return a specific language
    print "EXAMPLE 25:  Find and return schema " + schema_prefix

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, schemaptr, memberuri in collection(restobj, host,
                                                            '/redfish/v1/Schemas',
                                                            None,
                                                            login_account,
                                                            login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(schemaptr) == 'SchemaFile.0' or
        #        get_type(schemaptr) == 'SchemaFile.1')

        if schemaptr['Schema'].startswith(schema_prefix):
            for location in schemaptr['Location']:
                # this is an extref rather than an href because the actual
                # registries/schemas lie outside the data model
                extref_uri = location['Uri']['extref']
                status, headers, schema = rest_get(restobj, extref_uri, None)
                if status == 200:
                    print '\tFound ' + schema_prefix + ' at ' + extref_uri
                    return extref_uri, schema
                else:
                    print '\t' + schema_prefix + ' not found at ' + extref_uri
                    return None, None

    print 'Registry ' + schema_prefix + ' not found.'
    return None, None


def ex26_get_registry(restobj, host, login_account, login_password,
                      registry_prefix):

    # This could be augmented to return a specific language
    print "EXAMPLE 26:  Find and return registry " + registry_prefix

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, registryptr, memberuri in collection(
            restobj, host, '/redfish/v1/Registries', None, login_account,
            login_password):

        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(registryptr) == 'SchemaFile.0' or
        #        get_type(registryptr) == 'SchemaFile.1')

        if ('Schema' in registryptr and
                registryptr['Schema'].startswith(registry_prefix)):
            for location in registryptr['Location']:
                # this is an extref rather than an href because the actual
                # registries/schemas lie outside the data model
                extref_uri = location['Uri']['extref']
                status, headers, registry = rest_get(restobj, extref_uri, None)
                if status == 200:
                    print '\tFound ' + registry_prefix + ' at ' + extref_uri
                    return extref_uri, registry
                else:
                    print ('\t' + registry_prefix + ' not found at ' +
                           extref_uri)
                    return None, None

    print 'Registry ' + registry_prefix + ' not found.'
    return None, None


def ex27_set_ilo_timezone(restobj, host, olson_timezone, login_account,
                          login_password):
    # this only works if iLO is NOT configured to take time settings
    # from DHCP v4 or v6

    print "EXAMPLE 27:  Set iLO's Timezone"
    print ("\tNOTE:  This only works if iLO is NOT configured to take time "
           "settings from DHCP v4 or v6")

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        # for each system in the systems collection at /redfish/v1/Systems
        status, headers, datetime = rest_get(
            restobj, manager['Oem']['Hp']['Links']['DateTimeService']['@odata.id'],
            None)

        # print current time zone
        print '\tCurrent iLO timezone:  ' + datetime['TimeZone']['Name']

        # find time zone from list
        for timezone in datetime['TimeZoneList']:
            if timezone['Name'].startswith(olson_timezone):
                request = {'TimeZone': {'Index': timezone['Index']}}
                print (
                    'PATCH ' + json.dumps(request) + ' to ' +
                    manager['Oem']['Hp']['Links']['DateTimeService']['@odata.id'])
                status, headers, response = rest_patch(
                    restobj,
                    manager['Oem']['Hp']['Links']['DateTimeService']['@odata.id'],
                    request)
                print_extended_info(response)
                if status == 200:
                    print '\tiLO TimeZone set to ' + timezone['Name']
                return

        print '\tTimeZone value not found'


def ex28_set_ilo_ntp_servers(restobj, host, ntp_servers, login_account,
                             login_password):

    print "EXAMPLE 28:  Set iLO's NTP Servers"

    # for each system in the systems collection at /redfish/v1/Systems
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers',
                                                          None, login_account,
                                                          login_password):

        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(manager) == 'Manager.0' or
        #        get_type(manager) == 'Manager.1')

        # for each system in the systems collection at /redfish/v1/Systems
        status, headers, datetime = rest_get(
            restobj, manager['Oem']['Hp']['Links']['DateTimeService']['@odata.id'],
            None)

        # print current time zone
        print ('\tCurrent iLO Date/Time Settings:  ' +
               json.dumps(datetime['ConfigurationSettings']))
        print ('\tCurrent iLO NTP Servers:  ' +
               json.dumps(datetime['NTPServers']))

        request = {'StaticNTPServers': ntp_servers}
        print ('PATCH ' + json.dumps(request) + ' to ' +
               manager['Oem']['Hp']['Links']['DateTimeService']['@odata.id'])
        status, headers, response = rest_patch(
            restobj, manager['Oem']['Hp']['Links']['DateTimeService']['@odata.id'],
            request)
        print_extended_info(response)
        print ('\tChanges in pending settings require an iLO reset to become '
               'active.')


def ex29_get_powermetrics_average(restobj, host, login_account,
                                  login_password):

    # https://<host>/redfish/v1/Chassis/{item}/PowerMetrics#/PowerMetrics/
    #                                                     AverageConsumedWatts
    print "EXAMPLE 29:  Report PowerMetrics Average Watts"

    # for each chassis in the chassis collection at /redfish/v1/Chassis
    for status, headers, chassis, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Chassis',
                                                          None, login_account,
                                                          login_password):
        # verify expected type
        # hint:  Don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        #assert (get_type(chassis) == 'Chassis.0' or
        #        get_type(chassis) == 'Chassis.1')

        # for each chassis in the chassis collection at /redfish/v1/Chassis
        status, headers, pwrmetric = rest_get(
            restobj, chassis['Power']['@odata.id'], None)

        if ('PowerControl' not in pwrmetric or
                'PowerConsumedWatts' not in pwrmetric['PowerControl'][0]):
            print '\tPowerMetrics resource does not contain "PowerConsumedWatts"'
        else:
            print ('\t' + chassis['Model'] + ' PowerConsumedWatts = ' +
                   str(pwrmetric['PowerControl'][0]['PowerConsumedWatts']) +
                   'Watts')

def ex30_set_LicenseKey(restobj, host, login_account, login_password, iLO_Key):

    # https://<host>/redfish/v1/Manager/{item}/PowerMetrics#/PowerMetrics/AverageConsumedWatts
    print "EXAMPLE 30:  Set iLO License Key"

    # for each manager in the manager collection at /redfish/v1/Managers/
    for status, headers, manager, memberuri in collection(restobj, host,
                                                          '/redfish/v1/Managers/',
                                                          None, login_account,
                                                          login_password):
      # verify expected type
        # hint:  don't limit to version 0 here as we will rev to 1.0 at some
        #        point hopefully with minimal changes
        # assert (get_type(manager) == 'Manager.0' or
        #           get_type(manager) == 'Manager.1')

        # for each manager in the manager collection at /redfish/v1/Manager
        if '@odata.id' not in manager['Oem']['Hp']['Links']['LicenseService']:
            print '\t"LicenseService" section in Manager/Oem/Hp does not exist'
            return
        license_uri = manager['Oem']['Hp']['Links']['LicenseService']['@odata.id']
        for status, headers, licenseItem, memberuri in collection(restobj, host, license_uri,
                                                                  None, login_account,
                                                                  login_password):
            # verify expected type
            # hint:  don't limit to version 0 here as we will rev to 1.0 at some point
            #        hopefully with minimal changes
            #assert(get_type(licenseItem) == 'HpiLOLicense.0' or
            #       get_type(licenseItem) == 'HpiLOLicense.1')

            if 'LicenseKey' not in licenseItem:
                print '\tHpiLOLicense resource does not contain "LicenseKey" property'
            else:
                print '\tOld Key: "' + licenseItem['LicenseKey'] + '"'

        key = dict()
        key['LicenseKey'] = iLO_Key

        # perform the POST action
        print 'POST ' + json.dumps(key) + ' to ' + license_uri
        status, headers, response = rest_post(restobj, license_uri, None, key)
        print 'POST response = ' + str(status)
        print_extended_info(response)

        for status, headers, licenseItem, memberuri in collection(restobj, host, license_uri,
                                                                  None, login_account,
                                                                  login_password):
            # verify expected type
            # hint:  don't limit to version 0 here as we will rev to 1.0 at some point
            #        hopefully with minimal changes
            #assert(get_type(licenseItem) == 'HpiLOLicense.0' or
            #       get_type(licenseItem) == 'HpiLOLicense.1')

            if 'LicenseKey' not in licenseItem:
                print '\tHpiLOLicense resource does not contain "LicenseKey" property'
            else:
                print '\tNew Key: "' + licenseItem['LicenseKey'] + '"'
# Run the tests
if __name__ == '__main__':
    # Run the tests

    #Config logger used by HPE Restful SDK
    LOGGER = hpsdk.hpsdk_logger()
    LOGGER.setLevel(logging.INFO)
    fh = logging.FileHandler("HpRedfishApiExamples.log")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)
    LOGGER.info('HPE Redfish API examples')

    # commonly needed function values (typically would be passed in by
    # argument)
    ILO_HOST = 'https://16.84.217.223'
    ILO_ACCOUNT = 'admin'
    ILO_PASSWORD = 'admin123'
    BIOS_PASSWORD = None
    ISO_URI = 'http://16.83.60.69/jack/test.iso'

    print 'Tutorial Examples 0.9.12 BETA for HP RESTful API'
    print 'Copyright 2002-2016 Hewlett Packard Enterprise, L.P.'
    print 'For more information see www.hp.com/go/restfulapi'
    print ('Uncomment the ex* functions in the script file to see use case '
           'examples')

    # comment this out to get to the test cases - we just don't want to start
    # messing with any network endpoints without deliberate alteration
    # to enable.
    print 'NOTE:  Remove the sys.exit call here to run the test cases.'
    # sys.exit(-1)

    # Create a rest object
    REST_OBJ = create_object(ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)

    if True:
        # Get the message registries (we could just iterate through but for
        # convenience and clarity, we'll just grab 2 of them)
        # This is optional, but nice if you want to turn error structures into
        # nice strings
        REG_URI, MESSAGE_REGISTRIES['Base'] = ex26_get_registry(REST_OBJ,
                                                                ILO_HOST,
                                                                ILO_ACCOUNT,
                                                                ILO_PASSWORD,
                                                                'Base')
        REG_URI, MESSAGE_REGISTRIES['iLO'] = ex26_get_registry(REST_OBJ,
                                                               ILO_HOST,
                                                               ILO_ACCOUNT,
                                                               ILO_PASSWORD,
                                                               'iLO')
    if True:
        ex1_change_bios_setting(REST_OBJ, ILO_HOST, 'AdminName', 'Mr. Rest',
                                ILO_ACCOUNT, ILO_PASSWORD, BIOS_PASSWORD)
        ex2_reset_server(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)
        ex3_enable_secure_boot(REST_OBJ, ILO_HOST, False, ILO_ACCOUNT,
                               ILO_PASSWORD)
        ex4_bios_revert_default(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)
    if True:
        ex5_change_boot_order(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD,
                              BIOS_PASSWORD)

    if True:
        ex6_change_temporary_boot_order(REST_OBJ, ILO_HOST, 'Pxe', ILO_ACCOUNT,
                                        ILO_PASSWORD)
        ex6_change_temporary_boot_order(REST_OBJ, ILO_HOST, 'Hdd', ILO_ACCOUNT,
                                        ILO_PASSWORD)

    if True:
        ex7_find_ilo_mac_address(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)

    # iLO User Account Modification
    if True:
        # Create new account
        ex8_add_ilo_user_account(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD,
                                 'jjackson', 'John Jackson', 'newpassword',
                                 irc=True, cfg=True, virtual_media=True,
                                 usercfg=True, vpr=True)
        # change login name, user name, and password
        ex9_modify_ilo_user_account(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                    ILO_PASSWORD, 'jjackson',
                                    new_loginname='jjohnson',
                                    new_username='Jack Johnson',
                                    # change user/pass info
                                    new_password='adifferentpassword')
        # Remove some privileges
        ex9_modify_ilo_user_account(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                    ILO_PASSWORD, 'jjohnson', irc=False,
                                    virtual_media=False, usercfg=False)
        # Remove the account
        ex10_remove_ilo_account(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD,
                                'jjohnson')

    if True:
        ex11_dump_ilo_nic(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)
        ex12_sessions(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)
        ex13_set_uid_light(REST_OBJ, ILO_HOST, True, ILO_ACCOUNT,
                           ILO_PASSWORD)  # light it up
        ex13_set_uid_light(REST_OBJ, ILO_HOST, False, ILO_ACCOUNT,
                           ILO_PASSWORD)  # turn it off
        ex14_computer_details(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)

    # virtual media
    if True:
        # unmount (should fail with HTTP 400 of nothing is currently mounted)
        ex15_mount_virtual_media_iso(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                     ILO_PASSWORD)  # unmount
        # mount ISO - replace this with a valid URI to an ISO file
        ex15_mount_virtual_media_iso(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                     ILO_PASSWORD, ISO_URI,
                                     boot_on_next_server_reset=True)  # mount
        # unmount again
        ex15_mount_virtual_media_iso(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                     ILO_PASSWORD)  # unmount

    if True:
        ex16_set_server_asset_tag(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                  ILO_PASSWORD, 'SampleAssetTag')
        # Ex17 works. Disable it because iLO resetting will break the rest of the examples
        #ex17_reset_ilo(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)

    # Find iLO NIC (active/inactive, dedicated/shared)
    if True:
        # find and return the uri and resource of the currently active iLO NIC
        NIC_URI, CONTENT = ex18_get_ilo_nic(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                            ILO_PASSWORD)
        print 'Active\t' + NIC_URI + ": " + json.dumps(CONTENT)
        # set the Shared Network Port active
        ex19_set_active_ilo_nic(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD,
                                shared_nic=True)
        # set the Dedicated Network Port active
        ex19_set_active_ilo_nic(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD,
                                shared_nic=False)

    # Log dump and clearing
    if True:
        # dump both logs
        ex20_dump_iml(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)
        ex21_dump_ilo_event_log(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                ILO_PASSWORD)
        # clear both logs
        ex22_clear_iml(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)
        ex23_clear_ilo_event_log(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD)

    # SNMP Configuration
    if True:
        ex24_configure_snmp(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD,
                            snmp_mode='Agentless', snmp_alerts=False)

    # Get Schema
    if True:
        # getting all the schema from iLO is pretty slow - this is an example
        # of how to get one by name
        SCHEMA_URI, SCHEMA_OBJ = ex25_get_schema(REST_OBJ, ILO_HOST,
                                                 ILO_ACCOUNT, ILO_PASSWORD,
                                                 'ComputerSystem')

    if True:
        ex26_get_registry(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD, 'Base')
        ex26_get_registry(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD, 'iLO')
        ex26_get_registry(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD, 'HpBiosAttribute')

    # iLO TimeZone
    if True:
        ex27_set_ilo_timezone(REST_OBJ, ILO_HOST, 'America/Chicago',
                              ILO_ACCOUNT, ILO_PASSWORD)

    # iLO NTP Servers
    if True:
        ex28_set_ilo_ntp_servers(REST_OBJ, ILO_HOST, ['192.168.0.1',
                                                      '192.168.0.2'],
                                 ILO_ACCOUNT, ILO_PASSWORD)

    # Get average watts consumed.
    if True:
        ex29_get_powermetrics_average(REST_OBJ, ILO_HOST, ILO_ACCOUNT,
                                      ILO_PASSWORD)
        # commonly needed function values (typically would be passed
        # in by argument)
    # Install iLO LicenseKey
    if False:
        # Response 'InvalidLicenseKey' is expected because license is in incorrect format
        # We don't want to override current liscense key
        ex30_set_LicenseKey(REST_OBJ, ILO_HOST, ILO_ACCOUNT, ILO_PASSWORD, "testing_iLO_Key")

    REST_OBJ.logout()
