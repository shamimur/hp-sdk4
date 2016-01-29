# -*- coding: utf-8 -*-
""" Rmc implementation """

#---------Imports---------

import os
import json
import logging
import hashlib
import tempfile
import errno
import urlparse2
import hpsdk.rest
from .config import (AutoConfigParser)
from .ris import (RisMonolith)
from .types import (JSONEncoder)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class HprmcError(Exception):
    """ Baseclass for all hprmc Exceptions """
    errcode = 1
    def __init__(self, message):
        Exception.__init__(self, message)

class InvalidCommandLineError(HprmcError):
    """ Raised when user enter incorrect command line arguments """
    pass

class FailureDuringCommitError(HprmcError):
    """ Raised when there is an error while updating firmware """
    pass

class UndefinedClientError(Exception):
    """ Raised when there are no clients active
        (usually when user hasn't logged in) """
    pass

class InstanceNotFoundError(Exception):
    """ Raised when attempting to select an instance that does not exist. """
    pass

class CurrentlyLoggedInError(Exception):
    """ Raised when attempting to select an instance that does not exist. """
    pass

class NothingSelectedError(Exception):
    """ Raised when attempting to access an object
        without first selecting it """
    pass

class NothingSelectedFilterError(Exception):
    """ Raised when the filter applied doesn't match any selection """
    pass

class NothingSelectedSetError(Exception):
    """ Raised when attempting to access an object
        without first selecting it """
    pass

class InvalidSelectionError(Exception):
    """ Raised when selection argument fails to match anything """
    pass

class IdTokenError(Exception):
    """ Raised when bios password credentials have not been provided. """
    pass

class SessionExpired(Exception):
    """ Raised when bios password credentials have not been provided. """
    pass

class ValueChangedError(Exception):
    """ Raised if user tries to set/ commit un-updated value from monolith """
    pass

class LoadSkipSettingError(Exception):
    """ Raised when one or more settings are absent in given server """
    pass

class ValidationError(Exception):
    """ Raised when there is a problem with user input. """
    def __init__(self, errlist):
        super(ValidationError, self).__init__(errlist)
        self._errlist = errlist

    def get_errors(self):
        """ Wrapper function to return error list """
        return self._errlist

def _url2path(url):
    """ Function to convert given url to path """
    parts = urlparse2.urlparse(url)
    pathstr = '%s/%s' % (parts.netloc, parts.path)
    return pathstr.replace('//', '/')

class RmcClient(object):
    """ Constructor """
    def __init__(self, url=None, username=None, password=None, \
                                            biospassword=None, sessionkey=None,\
                                            is_redfish=False):
        self._base_url = url
        if is_redfish:
            self._rest_client = hpsdk.rest.v1.redfish_client(base_url=url,\
                                    username=username, password=password, \
                                    biospassword=biospassword, \
                                    sessionkey=sessionkey, is_redfish=is_redfish)
        else:
            self._rest_client = hpsdk.rest.v1.rest_client(base_url=url,\
                                    username=username, password=password,\
                                    biospassword=biospassword, \
                                    sessionkey=sessionkey, is_redfish=is_redfish)

        self._get_cache = dict()
        self._monolith = RisMonolith(self)
        self._selector = None
        self._filter_attr = None
        self._filter_value = None
        self._bios_password = biospassword

    def get_username(self):
        """ The rest client's current username. """
        return self._rest_client.get_username()

    def get_password(self):
        """ The rest client's current password. """
        return self._rest_client.get_password()

    def get_session_key(self):
        """ The rest client's current session key. """
        return self._rest_client._RestClientBase__session_key

    def get_session_location(self):
        """ The rest client's current session location. """
        return self._rest_client._RestClientBase__session_location

    def get_authorization_key(self):
        """ The rest client's current authorization key. """
        return self._rest_client._RestClientBase__authorization_key

    def get_base_url(self):
        """ The rest client's current base url """
        return self._base_url

    base_url = property(get_base_url, None)

    def get_cache_dirname(self):
        """ The rest client's current base url converted to path """
        return _url2path(self.get_base_url())

    def get_monolith(self):
        """ The rest client's current monolith """
        return self._monolith

    monolith = property(get_monolith, None)

    def login(self):
        """ Login using rest client. """
        self._rest_client.login(auth="session")

    def logout(self):
        """ Logout using rest client. """
        self._rest_client.logout()

    def get(self, path, args=None):
        """
        Perform a GET request on path argument.  If result is cached the data
        from the cache is returned instead.

        :param path: The URL to perform a GET request on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :returns: a RestResponse object containing the response data.
        :rtype: hpsdk.rest.v1.RestResponse.
        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp
        return resp

    def set(self, path, args=None, body=None, optionalpassword=None, \
                                                        providerheader=None):
        """
        Perform a PATCH request on path argument.

        :param path: The URL to perform a GET requst on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :param body: contents of the PATCH request.
        :type body: str.
        :returns: a RestResponse object containing the response data.
        :rtype: hpsdk.rest.v1.RestResponse.
        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.patch(path=path, args=args, body=body,\
                                       optionalpassword=optionalpassword, \
                                       providerheader=providerheader)

    def toolpost(self, path, args=None, body=None, providerheader=None):
        """
        Perform a POST request on path argument.

        :param path: The URL to perform a GET requst on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :param body: contents of the PUT request.
        :type body: str.
        :returns: a RestResponse object containing the response data.
        :rtype: hpsdk.rest.v1.RestResponse.
        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.post(path=path, args=args, body=body, \
                                                providerheader=providerheader)

    def toolput(self, path, args=None, body=None, optionalpassword=None, \
                                                        providerheader=None):
        """
        Perform a PUT request on path argument.

        :param path: The URL to perform a GET requst on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :param body: contents of the PUT request.
        :type body: str.
        :returns: a RestResponse object containing the response data.
        :rtype: hpsdk.rest.v1.RestResponse.
        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.put(path=path, args=args, body=body, \
                                     optionalpassword=optionalpassword, \
                                     providerheader=providerheader)

    def tooldelete(self, path, args=None, providerheader=None):
        """
        Perform a PUT request on path argument.

        :param path: The URL to perform a GET requst on.
        :type path: str.
        :param args: GET arguments.
        :type args: str.
        :param body: contents of the PUT request.
        :type body: str.
        :returns: a RestResponse object containing the response data.
        :rtype: hpsdk.rest.v1.RestResponse.
        """
        resp = self._rest_client.get(path=path, args=args)
        self._get_cache[path] = resp

        return self._rest_client.delete(path=path, args=args, \
                                                providerheader=providerheader)

    def _get_selector(self):
        """ The rest client's current selector """
        return self._selector

    def _set_selector(self, selectorval):
        """ Sets the rest client's selector """
        self._selector = selectorval
    selector = property(_get_selector, _set_selector)

    def _get_filter_attr(self):
        """ The rest client's current selector """
        return self._filter_attr

    def _set_filter_attr(self, filterattr):
        """ Sets the rest client's selector """
        self._filter_attr = filterattr
    filter_attr = property(_get_filter_attr, _set_filter_attr)

    def _get_filter_value(self):
        """ The rest client's current selector """
        return self._filter_value

    def _set_filter_value(self, filterval):
        """ Sets the rest client's selector """
        self._filter_value = filterval
    filter_value = property(_get_filter_value, _set_filter_value)

    def _get_bios_password(self):
        """ The rest client's second level password """
        return self._bios_password

    def _set_bios_password(self, biospasswordword):
        """ Sets the rest client's second level password """
        self._bios_password = biospasswordword
    bios_password = property(_get_bios_password, _set_bios_password)

class RmcConfig(AutoConfigParser):
    """ Rmc config object """
    def __init__(self, filename=None):
        AutoConfigParser.__init__(self, filename=filename)
        self._sectionname = 'hprest'
        self._configfile = filename
        if os.name == 'nt':
            self._ac__logdir = os.path.join(tempfile.gettempdir(), "hprest")
        else:
            self._ac__logdir = "/var/log/hprest"
        self._ac__cache = True
        self._ac__url = ''
        self._ac__username = ''
        self._ac__password = ''
        self._ac__commit = ''
        self._ac__format = ''
        self._ac__iloschemadir = ''
        self._ac__biosschemadir = ''
        self._ac__cachedir = ''
        self._ac__savefile = ''
        self._ac__loadfile = ''
        self._ac__biospasswordword = ''


    def get_configfile(self):
        """ The current configuration file """
        return self._configfile

    def set_configfile(self, config_file):
        """ Set the current configuration file """
        self._configfile = config_file

    def get_logdir(self):
        """ Get the current log directory """
        return self._get('logdir')

    def set_logdir(self, value):
        """ Set the current log directory """
        return self._set('logdir', value)

    def get_cache(self):
        """ Get the config file cache status """
        if isinstance(self._get('cache'), bool):
            return self._get('cache')
        else:
            return self._get('cache').lower() in ("yes", "true", "t", "1")

    def set_cache(self, value):
        """ Get the config file cache status """
        return self._set('cache', value)

    def get_url(self):
        """ Get the config file url """
        return self._get('url')

    def set_url(self, value):
        """ Set the config file url """
        return self._set('url', value)

    def get_username(self):
        """ Get the config file username """
        return self._get('username')

    def set_username(self, value):
        """ Set the config file username """
        return self._set('username', value)

    def get_password(self):
        """ Get the config file password """
        return self._get('password')

    def set_password(self, value):
        """ Set the config file password """
        return self._set('password', value)

    def get_commit(self):
        """ Get the config file commit status"""
        return self._get('commit')

    def set_commit(self, value):
        """ Set the config file commit status """
        return self._set('commit', value)

    def get_format(self):
        """ Get the config file default format """
        return self._get('format')

    def set_format(self, value):
        """ Set the config file default format """
        return self._set('format', value)

    def get_schemadir(self):
        """ Get the config file schema directory """
        return self._get('iloschemadir')

    def set_schemadir(self, value):
        """ Set the config file schema directory """
        return self._set('iloschemadir', value)

    def get_biosschemadir(self):
        """ Get the config file bios schema directory """
        return self._get('biosschemadir')

    def set_biosschemadir(self, value):
        """ Set the config file bios schema directory """
        return self._set('biosschemadir', value)

    def get_cachedir(self):
        """ Get the config file cache directory """
        return self._get('cachedir')

    def set_cachedir(self, value):
        """ Set the config file cache directory """
        return self._set('cachedir', value)

    def get_defaultsavefilename(self):
        """ Get the config file default save name """
        return self._get('savefile')

    def set_defaultsavefilename(self, value):
        """ Set the config file default save name """
        return self._set('savefile', value)

    def get_defaultloadfilename(self):
        """ Get the config file default load name """
        return self._get('loadfile')

    def set_defaultloadfilename(self, value):
        """ Set the config file default load name """
        return self._set('loadfile', value)

    def get_bios_password(self):
        """ Get the config file password """
        return self._get('biospasswordword')

    def set_bios_password(self, value):
        """ Set the config file password """
        return self._set('biospasswordword', value)

class RmcCacheManager(object):
    """ Manages caching / uncaching of data for RmcApp """
    def __init__(self, rmc):
        self._rmc = rmc

class RmcFileCacheManager(RmcCacheManager):
    """ Constructor """
    def __init__(self, rmc):
        super(RmcFileCacheManager, self).__init__(rmc)

    def logout_del_function(self, url=None):
        """ Helper function for logging out a specific url or all urls """
        cachedir = self._rmc.config.get_cachedir()
        indexfn = u'%s/index' % cachedir
        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, 'r')
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    if url:
                        if url in index['url']:
                            os.remove(os.path.join(cachedir, index['href']))
                            break
                    else:
                        os.remove(os.path.join(cachedir, index['href']))
            except BaseException, excp:
                self._rmc.warn(u'Unable to read cache data %s' % excp)

    def uncache_rmc(self):
        """ Simple monolith uncache function """
        cachedir = self._rmc.config.get_cachedir()
        indexfn = u'%s/index' % cachedir
        if os.path.isfile(indexfn):
            try:
                indexfh = open(indexfn, 'r')
                index_cache = json.load(indexfh)
                indexfh.close()

                for index in index_cache:
                    clientfn = index['href']
                    self._uncache_client(clientfn)
            except BaseException, excp:
                self._rmc.warn(u'Unable to read cache data %s' % excp)


    def _uncache_client(self, cachefn):
        """ Complex monolith uncache function """
        cachedir = self._rmc.config.get_cachedir()
        clientsfn = u'%s/%s' % (cachedir, cachefn)
        if os.path.isfile(clientsfn):
            try:
                clientsfh = open(clientsfn, 'r')
                clients_cache = json.load(clientsfh)
                clientsfh.close()

                for client in clients_cache:
                    if u'login' not in client:
                        continue

                    login_data = client['login']
                    if u'url' not in login_data:
                        continue

                    rmc_client = RmcClient(
                        username=login_data.get('username', 'Administrator'),
                        password=login_data.get('password', None),
                        url=login_data.get('url', None),
                        biospassword=login_data.get('bios_password', None),
                        sessionkey=login_data.get('session_key', None)
                    )
                    rmc_client._rest_client._authorization_key = \
                        login_data.get('authorization_key')
                    rmc_client._rest_client._session_key = \
                        login_data.get('session_key')
                    rmc_client._rest_client._session_location = \
                        login_data.get('session_location')

                    if u'selector' in client:
                        rmc_client.selector = client['selector']

                    if u'filter_attr' in client:
                        rmc_client.filter_attr = client['filter_attr']

                    if u'filter_value' in client:
                        rmc_client.filter_value = client['filter_value']

                    getdata = client['get']
                    rmc_client._get_cache = dict()
                    for key in getdata.keys():
                        restreq = hpsdk.rest.v1_helper.RestRequest(method='GET', path=key)
                        getdata[key]['restreq'] = restreq
                        rmc_client._get_cache[key] = \
                            hpsdk.rest.v1_helper.StaticRestResponse(**getdata[key])

                    rmc_client._monolith = RisMonolith(rmc_client)
                    rmc_client._monolith.load_from_dict(client['monolith'])

                    self._rmc._rmc_clients.append(rmc_client)

            except BaseException, excp:
                self._rmc.warn(u'Unable to read cache data %s' % excp)

    def cache_rmc(self):
        """ Caching funciton for monolith """
        if not self._rmc.config.get_cache():
            return

        cachedir = self._rmc.config.get_cachedir()
        if not os.path.isdir(cachedir):
            try:
                os.makedirs(cachedir)
            except OSError, ex:
                if ex.errno == errno.EEXIST:
                    pass
                else:
                    raise

        index_map = dict() # dict to prevent recalculating the md5
        index_cache = list()
        for client in self._rmc._rmc_clients:
            md5 = hashlib.md5()
            md5.update(client.get_base_url())
            md5str = md5.hexdigest()
            index_map[client.get_base_url()] = md5str
            index_data = dict(
                url=client.get_base_url(),
                href=u'%s' % md5str,
            )
            index_cache.append(index_data)


        indexfh = open(u'%s/index' % cachedir, 'w')
        json.dump(index_cache, indexfh, indent=2, cls=JSONEncoder)
        indexfh.close()

        clients_cache = list()

        if self._rmc._rmc_clients:
            for client in self._rmc._rmc_clients:
                login_data = dict(
                    username=client.get_username(),
                    password=client.get_password(),
                    url=client.get_base_url(),
                    session_key=client.get_session_key(),
                    session_location=client.get_session_location(),
                    authorization_key=client.get_authorization_key(),
                    bios_password=client._bios_password,\
                )
                clients_cache.append(\
                    dict(selector=client.selector, login=login_data,\
                          filter_attr=client._filter_attr,\
                          filter_value=client._filter_value,\
                          monolith=client.monolith, get=client._get_cache))

                clientsfh = open(u'%s/%s' % \
                            (cachedir, index_map[client.get_base_url()]), 'w')
                json.dump(clients_cache, clientsfh, indent=2, cls=JSONEncoder)
                clientsfh.close()
