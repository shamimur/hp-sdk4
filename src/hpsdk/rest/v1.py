###
# (C) Copyright (2012-2015) Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
###

# -*- coding: utf-8 -*-
""" Module for working with ProLiant REST technology. """

#---------Imports---------

import logging
from hpsdk.rest.v1_helper import get_client_instance

#---------End of imports---------


#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

#HP ENTRY POINT
ROOT_ENDPOINT = '/rest/v1'

#REDFISH ROOT ENTRY POINT
#ROOT_ENDPOINT = '/redfish/v1/'

def rest_client(base_url=None, username=None, password=None,
                default_prefix='/rest/v1', biospassword=None,
                sessionkey=None, is_redfish=False):
    """ An client instance will be returned for RESTful API

        :param base_url: rest host or ip address.
        :type base_url: str.
        :param username: username rquired to login to server
        :type: str
        :param password: password credentials required to login
        :type password: str
        :param default_prefix: default root to extract tree
        :type default_prefix: str
        :param biospassword: BIOS password for the server if set
        :type biospassword: str
        :param sessionkey: session key credential for current login
        :type sessionkey: str
        :returns: a client object for HP RESTful API
    """
    return get_client_instance(base_url, username, password,
                               default_prefix, biospassword,
                               sessionkey, is_redfish=False)

def redfish_client(base_url=None, username=None, password=None,
                   default_prefix='/redfish/v1/',
                   biospassword=None, sessionkey=None, is_redfish=True):
    """ An client Instance will be returned for Redfish API

    Every request sent by this instance will contain a Redfish specific header (Odata)

        :param base_url: rest host or ip address.
        :type base_url: str.
        :param username: username rquired to login to server
        :type: str
        :param password: password credentials required to login
        :type password: str
        :param default_prefix: default root to extract tree
        :type default_prefix: str
        :param biospassword: BIOS password for the server if set
        :type biospassword: str
        :param sessionkey: session key credential for current login
        :type sessionkey: str
        :returns: a client object for Redfish API
    """
    return get_client_instance(base_url, username, password,
                               default_prefix, biospassword,
                               sessionkey, is_redfish=True)
