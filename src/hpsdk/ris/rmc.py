# -*- coding: utf-8 -*-
""" Rmc implementation """

#---------Imports---------
import os
import re
import sys
import time
import copy
import logging
import jsonpatch
import jsonpath_rw
import jsonpointer

import hpsdk.ris.validation
import hpsdk.rest.v1

from collections import (OrderedDict, Mapping)
from hpsdk.ris.validation import (ValidationManager, RepoRegistryEntry)
from hpsdk.ris.rmc_helper import (UndefinedClientError, InstanceNotFoundError,
                                  CurrentlyLoggedInError, NothingSelectedError,
                                  InvalidSelectionError, IdTokenError,
                                  SessionExpired, ValidationError,
                                  RmcClient, RmcConfig, RmcFileCacheManager,
                                  NothingSelectedSetError, ValueChangedError,
                                  LoadSkipSettingError, InvalidCommandLineError,
                                  FailureDuringCommitError)

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class RmcApp(object):
    """ Application level implemenation of Rmc """
    def __init__(self, Args=None):
        self._rmc_clients = []
        configfile = None

        foundsomething = False
        for item in Args:
            if foundsomething:
                configfile = item
                break

            if item == "-c":
                foundsomething = True
            elif item.startswith("--config="):
                configfile = item.split("=", 1)[1]
                break
            elif item == "--config":
                foundsomething = True

        # use the default config file
        if configfile == None:
            if os.name == 'nt':
                configfile = os.path.join(os.path.dirname(sys.executable), \
                                                                 'hprest.conf')
            else:
                configfile = '/etc/hprest/hprest.conf'

        if not os.path.isfile(configfile):
            self.warn("Config file '%s' not found\n\n" % configfile)

        self._config = RmcConfig()
        self.config_file = configfile
        self.logger = logging.getLogger()
        self._cm = RmcFileCacheManager(self)
        self._monolith = None
        self._multilevelbuffer = None

    def restore(self):
        """ Restore monolith from cache """
        self._cm.uncache_rmc()

    def deletelogoutfunction(self, url=None):
        """ Wrapper function for logout helper function """
        self._cm.logout_del_function(url)

    def save(self):
        """ Cache curernt monolith build """
        self._cm.cache_rmc()

    def out(self):
        """ Helper function for runtimerror """
        raise RuntimeError(
            "You must override this method in your derived class"
        )

    def err(self, msg, inner_except=None):
        """ Helper function for runtimerror """
        LOGGER.error(msg)
        if inner_except is not None:
            LOGGER.error(inner_except)

    def warn(self, msg, inner_except=None):
        """ Helper function for runtimerror """
        LOGGER.warn(msg)
        if inner_except is not None:
            LOGGER.warn(inner_except)

    def get_config(self):
        """ Return config """
        return self._config

    config = property(get_config, None)

    def get_cache(self):
        """ Return config """
        return self._config

    config = property(get_cache, None)

    def config_from_file(self, filename):
        """ Get config from file """
        self._config = RmcConfig(filename=filename)
        self._config.load()

    def add_rmc_client(self, client):
        """ Add new rmc client """
        for i in range(0, len(self._rmc_clients)):
            if client.get_base_url() == self._rmc_clients[i].get_base_url():
                self._rmc_clients[i] = client
                return

        # not found so add it
        self._rmc_clients.append(client)

    def remove_rmc_client(self, url=None):
        """ Remove rmc client """
        if url:
            for i in range(0, len(self._rmc_clients)):
                if url in self._rmc_clients[i].get_base_url():
                    del self._rmc_clients[i]
        else:
            if self._rmc_clients and len(self._rmc_clients) > 0:
                self._rmc_clients = self._rmc_clients[:-1]

    def get_rmc_client(self, url):
        """
        Return rmc_client with the provided url.

        :param url: The URL of the client you are searching for.
        :type url: str.
        """
        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                return self._rmc_clients[i]

        # not found so add it
        return None

    def check_current_rmc_client(self, url):
        """
        Return rmc_client count.
        """
        if not len(self._rmc_clients):
            return True

        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                return True

        return False

    def update_rmc_client(self, url, **kwargs):
        """ Do update to passed client """
        for i in range(0, len(self._rmc_clients)):
            if url == self._rmc_clients[i].get_base_url():
                if 'username' in kwargs:
                    self._rmc_clients[i]._rest_client.username = \
                                                             kwargs['username']

                if 'password' in kwargs:
                    self._rmc_clients[i]._rest_client.password = \
                                                            kwargs['password']

                if 'biospassword' in kwargs:
                    self._rmc_clients[i]._rest_client.biospassword = \
                                                        kwargs['biospassword']

    def get_current_client(self):
        """ Get current client """
        if len(self._rmc_clients) > 0:
            return self._rmc_clients[-1]
        raise UndefinedClientError()
    current_client = property(get_current_client, None)

    def login(self, username=None, password=None, base_url=u'blobstore://.',
              verbose=False, path=None, biospassword=None, skipbuild=False,
              includelogs=False, is_redfish=False):
        """ Main worker function for login command """
        if not self.check_current_rmc_client(url=base_url):
            raise CurrentlyLoggedInError("Currently logged into another " \
             "server. \nPlease log out out first before logging in to another.")

        existing_client = self.get_rmc_client(url=base_url)
        if existing_client:
            self.update_rmc_client(url=base_url, username=username,
                                   password=password, biospassword=biospassword)
        else:
            try:
                self.add_rmc_client(RmcClient(username=username,
                                              password=password, url=base_url, \
                                              biospassword=biospassword, is_redfish=is_redfish))
            except Exception, excp:
                raise excp

        try:
            if base_url == "blobstore://." and float(self.getiloversion(skipschemas=True)) >= 2.20:
                self.current_client.login()
            elif username and password:
                self.current_client.login()
        except Exception, excp:
            raise excp

        if not skipbuild:
            self.build_monolith(verbose=verbose, path=path, \
                                                        includelogs=includelogs)
            self.save()

    def build_monolith(self, verbose=False, path=None, includelogs=False):
        """ Run through the ris tree to build monolith """
        monolith = self.current_client.monolith
        timetaken = time.clock()
        monolith.load(path=path, includelogs=includelogs)

        if verbose:
            sys.stdout.write(u"Monolith build process time: %s\n" % \
                             (time.clock() - timetaken))

    def logout(self, url=None):
        """ Main function for logout command """
        try:
            self.current_client.logout()
        except Exception:
            pass

        self.deletelogoutfunction(url)
        self.remove_rmc_client(url)
        self.save()

        cachedir = self.config.get_cachedir()
        if cachedir:
            try:
                os.remove(os.path.join(cachedir, 'index'))
                os.rmdir(cachedir)
            except Exception:
                pass
    def get(self, selector=None):
        """ Main function for get command """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            currdict = instance.resp.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if selector:
                jsonpath_expr = jsonpath_rw.parse(u'%s' % selector)
                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()
                for match in matches:
                    json_pstr = u'/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node
                    results.append(temp_dict)
            else:
                results.append(currdict)

        return results

    def get_save(self, selector=None, currentoverride=False, pluspath=False,
                 onlypath=None):
        """ Special main function for get in save command """
        results = list()

        instances = self.get_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.get_save_helper(instance.resp.request.path, instances)\
                                                     and not currentoverride:
                continue
            elif onlypath:
                if not onlypath == instance.resp.request.path:
                    continue

            currdict = instance.resp.dict

            # apply patches to represent current edits
            for patch in instance.patches:
                currdict = jsonpatch.apply_patch(currdict, patch)

            if selector:
                for item in currdict.iterkeys():
                    if selector.lower() == item.lower():
                        selector = item
                        break

                try:
                    jsonpath_expr = jsonpath_rw.parse(u'"%s"' % selector)
                except Exception, excp:
                    raise InvalidCommandLineError(excp)
                matches = jsonpath_expr.find(currdict)
                temp_dict = OrderedDict()
                for match in matches:
                    json_pstr = u'/%s' % match.full_path
                    json_node = jsonpointer.resolve_pointer(currdict, json_pstr)
                    temp_dict[str(match.full_path)] = json_node
                results.append(temp_dict)
            else:
                if pluspath:
                    results.append({instance.resp.request.path: currdict})
                else:
                    results.append(currdict)

        return results

    def get_save_helper(self, path, instances):
        """helper function for save helper"""
        skip = False

        for item in instances:
            if (path + "/settings").lower() == (item.resp.request.path).lower():
                skip = True
                break

        return skip

    def set(self, selector=None, val=None, latestschema=False, uniqueoverride=False):
        """ Main function for set command """
        results = list()
        regloc = None
        nochangesmade = False
        patchremoved = False
        iloversion = self.getiloversion()
        type_str = self.current_client.monolith._typestring
        validation_manager = self.get_validation_manager(iloversion)
        (instances, _) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        if selector:
            for instance in instances:
                self.checkforetagchange(instance=instance)

        (instances, attributeregistry) = self.get_selection(setenable=True)
        if selector:
            for instance in instances:
                skip = False
                try:
                    if not "PATCH" in instance.resp._http_response.msg.headers[0]:
                        sys.stdout.write(u'Skipping read-only path: %s\n' % \
                                                    instance.resp.request.path)
                        skip = True
                except Exception:
                    try:
                        for item in instance.resp._headers:
                            if item.keys()[0] == "allow":
                                if not "PATCH" in item.values()[0]:
                                    sys.stdout.write(u'Skipping read-only path:'\
                                          ' %s\n' % instance.resp.request.path)
                                    skip = True
                                    break
                    except Exception:
                        if not "PATCH" in instance.resp._headers["allow"]:
                            sys.stdout.write(u'Skipping read-only path: %s\n' % \
                                                    instance.resp.request.path)
                            skip = True

                if skip:
                    continue
                else:
                    nochangesmade = True

                currdict = instance.resp.dict
                if latestschema:
                    schematype = currdict[type_str].split('.')[0]
                    reglist = validation_manager._classes_registry[0][u'Items']

                    for item in validation_manager._classes[0][u'Items']:
                        if item[u'Id'].startswith(schematype):
                            schematype = item[u'Schema']
                            break

                    regs = [x[u'Schema'] for x in reglist if x[u'Schema']\
                            .lower().startswith('hpbiosattributeregistry')]
                    i = [reglist.index(x) for x in reglist if x[u'Schema']\
                         .lower().startswith('hpbiosattributeregistry')]
                    regs = zip(regs, i)

                    for item in sorted(regs, reverse=True):
                        extref = self.get_handler(reglist[item[1]][u'Location']\
                                    [0]["Uri"]["extref"], \
                                    verbose=False, service=True, silent=True)
                        if extref:
                            regtype = item[0]
                            break
                else:
                    schematype = currdict[type_str]
                    try:
                        regtype = attributeregistry[instance.type]
                    except Exception:
                        pass
                try:
                    if attributeregistry[instance.type]:
                        regfound = validation_manager.\
                            find_bios_registry(regtype)
                except Exception:
                    regfound = \
                            validation_manager.find_schema(schematype)
                if self.current_client.monolith.is_redfish and regfound:
                    regfound = self.get_handler(regfound[u'@odata.id'], \
                        verbose=False,service=True,silent=True).obj
                    regloc = regfound

                    regfound = RepoRegistryEntry(regfound)
                if not regfound:
                    LOGGER.warn(u"Unable to locate registry/schema for '%s'", \
                        currdict[type_str])
                    continue
                elif float(iloversion) >= 2.10:
                    try:
                        self.check_type_and_download(\
                                         self.current_client.monolith, \
                                        regfound.Location[0]["Uri"]["extref"], \
                                        skipcrawl=True, loadtype='ref')
                    except Exception, excp:
                        raise excp

                for item in currdict.iterkeys():
                    if selector.lower() == item.lower():
                        selector = item
                        break

                newdict = currdict.copy()
                jsonpath_expr = jsonpath_rw.parse(u'%s' % selector)
                matches = jsonpath_expr.find(currdict)

                if not matches:
                    sys.stderr.write("Property not found in selection '%s', " \
                                 "skipping '%s'\n" % (instance.type, selector))
                    nochangesmade = False

                for match in matches:
                    newdict = currdict.copy()
                    json_pstr = u'/%s' % match.full_path

                    listfound = False
                    val = self.checkforintvalue(selector, val, iloversion, \
                                                validation_manager, instance)
                    if val:
                        if str(val)[0] == "[" and str(val)[-1] == "]":
                            json_node = jsonpointer.set_pointer(newdict, \
                                json_pstr, '"' + str(val) + '"', inplace=True)
                        else:
                            listfound = True
                    else:
                        listfound = True

                    if listfound:
                        json_node = jsonpointer.set_pointer(newdict, json_pstr, \
                                                        val, inplace=True)

                    json_node = jsonpointer.resolve_pointer(newdict, json_pstr)

                    entrydict = None
                    entrymono = None

                    if float(iloversion) >= 2.10:
                        entrydict = currdict
                        entrymono = self.current_client.monolith

                    try:
                        if attributeregistry[instance.type]:
                            vr = validation_manager.bios_validate(\
                                            newdict, \
                                            attributeregistry[instance.type], \
                                            selector, currdict=entrydict, \
                                            monolith=entrymono)
                            if vr == 'readonly':
                                sys.stderr.write("Property is read-only" \
                                             " skipping '%s'\n" % selector)
                                continue
                            elif vr == 'unique' and not uniqueoverride:
                                sys.stderr.write("Property is unique to the "\
                                                 "system skipping '%s'\n" \
                                                                    % selector)
                                continue
                    except Exception:
                        if not validation_manager.validate(newdict, \
                                                           selector=selector, \
                                                           currdict=entrydict, \
                                                           monolith=entrymono, \
                                                           regloc = regloc):
                            sys.stderr.write("Property is " \
                                        "read-only skipping '%s'.\n" % selector)
                            continue

                    validation_errors = validation_manager.get_errors()
                    if validation_errors and len(validation_errors) > 0:
                        raise ValidationError(validation_errors)

                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            if patch == item:
                                return
                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({selector:json_node})
                    if not patch:
                        for item in instance.patches:
                            try:
                                entry = item.patch[0]["path"].replace('/', '')
                                value = item.patch[0]["value"]
                            except Exception:
                                entry = item[0]["path"].replace('/', '')
                                value = item[0]["value"]

                            if entry == selector and str(value) not in str(val):
                                if currdict[selector] == val:
                                    instance.patches.remove(item)
                                    patchremoved = True
                                    nochangesmade = True
        if not nochangesmade:
            return "No entries found"
        if patchremoved:
            return "reverting"
        else:
            return results

    def loadset(self, dicttolist=None, selector=None, val=None, newargs=None,\
                latestschema=False, uniqueoverride=False):
        """ Optimized version of the old style of set properties """
        results = list()

        if (selector and val) and not dicttolist:
            dicttolist = [(selector, val)]
        elif dicttolist == None and not newargs:
            return results
        elif (selector and val and dicttolist) or (newargs and not val):
            return False

        nochangesmade = False
        iloversion = self.getiloversion()
        biosmode = False
        settingSkipped = False
        validation_manager = self.get_validation_manager(iloversion)
        (instances, _) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedSetError()

        if selector:
            for instance in instances:
                self.checkforetagchange(instance=instance)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        newarg = None
        if newargs:
            (name, _) = newargs[-1].split('=')
            outputline = '/'.join(newargs[:-1]) + "/" + name
            newarg = newargs[:-1]
            newarg.append(name)
            dicttolist = [(name, val)]

        for instance in instances:
            skip = False
            try:
                if not "PATCH" in instance.resp._http_response.msg.headers[0]:
                    sys.stdout.write(u'Skipping read-only path: %s\n' % \
                                                    instance.resp.request.path)
                    skip = True
            except Exception:
                try:
                    for item in instance.resp._headers:
                        if item.keys()[0] == "allow":
                            if not "PATCH" in item.values()[0]:
                                sys.stdout.write(u'Skipping read-only path:'\
                                          ' %s\n' % instance.resp.request.path)
                                skip = True
                                break
                except Exception:
                    if not "PATCH" in instance.resp._headers["allow"]:
                        sys.stdout.write(u'Skipping read-only path: %s\n' % \
                                                    instance.resp.request.path)
                        skip = True
            if skip:
                continue
            else:
                nochangesmade = True

            currdict = instance.resp.dict
            model, biosmode, _ = self.get_model(currdict, validation_manager, \
                                    instance, iloversion, \
                                    attributeregistry, latestschema, \
                                    newarg)

            if model:
                if biosmode:
                    validator = map(model.get_validator_bios, (x[0] for x in \
                                  dicttolist))
                else:
                    validator = map(model.get_validator, (x[0] for x in \
                                  dicttolist))

                if validator:
                    try:
                        convert = [isinstance(x, hpsdk.ris.validation.\
                                      IntegerValidator) for x in validator]
                        indices = [i for i, j in enumerate(convert) if j]
                        for item in indices:
                            dicttolist[item] = (dicttolist[item][0], \
                                                    int(dicttolist[item][1]))
                    except Exception:
                        convert = [isinstance(x, hpsdk.ris.validation.\
                                      IntegerValidator) for x in validator]
                        indices = [i for i, j in enumerate(convert) if j]

                        for item in indices:
                            if not dicttolist[item][1]:
                                dicttolist[item] = (dicttolist[item][0], \
                                                    dicttolist[item][1])
                            else:
                                dicttolist[item] = (dicttolist[item][0], \
                                                    int(dicttolist[item][1]))

            currdictcopy = copy.deepcopy(currdict)
            if newargs:
                for i in range(len(newargs)):
                    for item in currdictcopy.iterkeys():
                        if newarg[i].lower() == item.lower():
                            newarg[i] = item
                            if not i == (len(newargs) - 1):
                                currdictcopy = currdictcopy[item]
                            else:
                                dicttolist = [(item, dicttolist[0][1])]
                            break
            else:
                items = currdict.keys()
                items = sorted(items)
                itemslower = [x.lower() for x in items]
                templist = []
                try:
                    for item in range(len(dicttolist)):
                        try:
                            if not isinstance(dicttolist[item][1], list):
                                dicttolist[item] = items[itemslower.index(\
                                            dicttolist[item][0].lower())],\
                                            dicttolist[item][1]
                            else:
                                templist.append(dicttolist[item][0])
                        except ValueError, excp:
                            sys.stderr.write("Skipping propertry {0}, not found"\
                                                "in current server.\n".format(\
                                                        dicttolist[item][0]))
                            templist.append(dicttolist[item][0])
                            settingSkipped = True
                            pass

                    if templist:
                        [dicttolist.remove(x) for x in dicttolist if x[0] in \
                                                                    templist]
                except Exception, excp:
                    raise excp

            selectors = [x[0] for x in dicttolist]
            readonly = list()
            if model and biosmode:
                for item in model.Attributes:
                    try:
                        if (item["Name"] in selectors) and item["ReadOnly"]:
                            readonly.extend(item["Name"])
                            sys.stderr.write("Property is read-only" \
                                             " skipping '%s'\n" % item["Name"])
                            [dicttolist.remove(x) for x in dicttolist \
                                                        if x[0] == item["Name"]]
                        try:
                            if (item["Name"] in selectors) and \
                                                item["IsSystemUniqueProperty"] \
                                                and not uniqueoverride:
                                sys.stderr.write("Property is unique to the "\
                                                 "system skipping '%s'\n" % \
                                                                item["Name"])
                                [dicttolist.remove(x) for x in dicttolist \
                                                        if x[0] == item["Name"]]
                        except Exception:
                            continue
                    except Exception, excp:
                        raise excp
            elif model:
                for x in selectors:
                    try:
                        if model[x].readonly:
                            templist.append(x)
                    except Exception:
                        templist.append(x)
                try:
                    if templist:
                        tempdict = copy.deepcopy(dicttolist)
                        for i in templist:
                            sys.stderr.write("Property is read-only skipping "\
                                             "'%s'\n" % str(i))
                        [dicttolist.remove(x) for x in tempdict if x[0] in templist]
                except Exception, excp:
                    raise excp

            if len(dicttolist) < 1:
                return results

            oridict = copy.deepcopy(currdict)
            newdict = copy.deepcopy(currdict)
            patch = None
            if newargs:
                self._multilevelbuffer = newdict
                matches = self.setmultiworker(newargs, self._multilevelbuffer)
                if not matches:
                    sys.stderr.write("Property not found in selection '%s', " \
                                "skipping '%s'\n" % (instance.type, outputline))
                dicttolist = []
            for (itersel, iterval) in dicttolist:
                jsonpath_expr = jsonpath_rw.parse(u'%s' % itersel)
                matches = jsonpath_expr.find(currdict)

                if not matches:
                    sys.stderr.write("Property not found in selection '%s', " \
                                 "skipping '%s'\n" % (instance.type, itersel))
                    nochangesmade = False

                for match in matches:
                    json_pstr = u'/%s' % match.full_path

                    listfound = False
                    if iterval:
                        if str(iterval)[0] == "[" and str(iterval)[-1] == "]":
                            json_node = jsonpointer.set_pointer(newdict, \
                                json_pstr, '"' + str(iterval) + '"', inplace=True)
                        else:
                            listfound = True
                    else:
                        listfound = True

                    if listfound:
                        json_node = jsonpointer.set_pointer(newdict, json_pstr, \
                                                        iterval, inplace=True)

                    json_node = jsonpointer.resolve_pointer(newdict, json_pstr)

                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                            patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({itersel:json_node})
                    currdict = newdict.copy()

            entrydict = None
            entrymono = None

            if float(iloversion) >= 2.10:
                entrydict = oridict
                entrymono = self.current_client.monolith

            try:
                if attributeregistry[instance.type]:
                    validation_manager.bios_validate(newdict, \
                        attributeregistry[instance.type], checkall=True, \
                        currdict=entrydict, monolith=entrymono)
            except Exception:
                validation_manager.validate(newdict, checkall=True, \
                        currdict=entrydict, monolith=entrymono)

            validation_errors = validation_manager.get_errors()
            if validation_errors and len(validation_errors) > 0:
                raise ValidationError(validation_errors)

            if newargs and not dicttolist:
                patch = jsonpatch.make_patch(currdict, newdict)
                if patch:
                    for item in instance.patches:
                        try:
                            if item[0]["path"] == patch.patch[0]["path"]:
                                instance.patches.remove(item)
                        except Exception:
                            if item.patch[0]["path"] == \
                                                    patch.patch[0]["path"]:
                                instance.patches.remove(item)

                    instance.patches.append(patch)
                    results.append({outputline:val})

        if not nochangesmade:
            return "No entries found"
        elif settingSkipped == True:
            raise LoadSkipSettingError()
        else:
            return results

    def checkforintvalue(self, selector, val, iloversion, validation_manager, \
                                                    instance, newarg=None):
        """ Function for integer validation """
        biosmode = False
        currdict = instance.resp.dict
        (_, attributeregistry) = self.get_selection(setenable=True)

        try:
            if attributeregistry[instance.type]:
                regfound = validation_manager.\
                            find_bios_registry(attributeregistry[instance.type])
                biosmode = True
        except:
            regfound = validation_manager.find_schema(currdict[instance._typestring])

            if self.current_client.monolith.is_redfish and regfound:
                    regfound = self.get_handler(regfound[u'@odata.id'], \
                        verbose=False,service=True,silent=True).obj
        if regfound:
            model, _, _ = self.get_model(currdict, validation_manager, \
                                    instance, iloversion, attributeregistry)

            if model:
                if biosmode:
                    validator = model.get_validator_bios(selector)
                else:
                    validator = model.get_validator(selector, newarg)

                if validator:
                    try:
                        if isinstance(validator, hpsdk.ris.validation.\
                                      IntegerValidator):
                            val = int(val)
                    except Exception:
                        if isinstance(validator, hpsdk.ris.validation.\
                                      IntegerValidator):
                            if val:
                                val = int(val)


        return val

    def setmultilevel(self, val=None, newargs=None, latestschema=False):
        """ Main function for set multi level command """
        results = list()
        selector = None
        regloc = None
        nochangesmade = False
        patchremoved = False
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)
        type_string = self.current_client.monolith._typestring
        (name, _) = newargs[-1].split('=', 1)

        outputline = '/'.join(newargs[:-1]) + "/" + name

        (instances, _) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        if newargs:
            for instance in instances:
                self.checkforetagchange(instance=instance)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        if newargs:
            for instance in instances:
                currdict = instance.resp.dict
                currdictcopy = currdict
                newarg = newargs[:-1]
                newarg.append(name)
                for i in range(len(newargs)):
                    for item in currdictcopy.iterkeys():
                        if newarg[i].lower() == item.lower():
                            selector = item
                            newarg[i] = item
                            if not newarg[i].lower() == newarg[-1].lower():
                                currdictcopy = currdictcopy[item]
                                break
                if not selector:
                    continue
                skip = False
                val = self.checkforintvalue(selector, val, iloversion, \
                                    validation_manager, instance, newarg)
                try:
                    if not "PATCH" in \
                    instance.resp._http_response.msg.headers[0]:
                        sys.stdout.write(u'Skipping read-only path: %s\n' \
                                         % instance.resp.request.path)
                        skip = True
                except Exception:
                    try:
                        for item in instance.resp._headers:
                            if item.keys()[0] == "allow":
                                if not "PATCH" in item.values()[0]:
                                    sys.stdout.write(u'Skipping read-only \
                                    path: %s\n' % instance.resp.request.path)
                                    skip = True
                                    break
                    except Exception:
                        if not "PATCH" in instance.resp._headers["allow"]:
                            sys.stdout.write(u'Skipping read-only path: %s\n' \
                                             % instance.resp.request.path)
                            skip = True

                if skip:
                    continue
                else:
                    nochangesmade = True

                if latestschema:
                    schematype = currdict[type_string].split('.')[0]
                    reglist = validation_manager._classes_registry[0][u'Items']

                    for item in validation_manager._classes[0][u'Items']:
                        if item[u'Id'].startswith(schematype):
                            schematype = item[u'Schema']
                            break

                    regs = [x[u'Schema'] for x in reglist if x[u'Schema']\
                            .lower().startswith('hpbiosattributeregistry')]
                    i = [reglist.index(x) for x in reglist if x[u'Schema']\
                         .lower().startswith('hpbiosattributeregistry')]
                    regs = zip(regs, i)

                    for item in sorted(regs, reverse=True):
                        extref = self.get_handler(reglist[item[1]][u'Location']\
                                    [0]["Uri"]["extref"], \
                                    verbose=False, service=True, silent=True)
                        if extref:
                            regtype = item[0]
                            break
                else:
                    schematype = currdict[type_string]
                    try:
                        regtype = attributeregistry[instance.type]
                    except Exception:
                        pass

                try:
                    if attributeregistry[instance.type]:
                        regfound = validation_manager.find_bios_registry(regtype)
                except Exception:
                    regfound = validation_manager.find_schema(schematype)

                if self.current_client.monolith.is_redfish and regfound:
                    regfound = self.get_handler(regfound[u'@odata.id'], \
                        verbose=False,service=True,silent=True).obj
                    regloc = regfound
                if not regfound:
                    LOGGER.warn(u"Unable to locate registry/schema for '%s'",\
                                                            currdict[u'Type'])
                    continue
                elif float(iloversion) >= 2.10:
                    try:
                        self.check_type_and_download(\
                                self.current_client.monolith, \
                                regfound.Location[0]["Uri"]["extref"], \
                                skipcrawl=True, loadtype='ref')
                    except Exception, excp:
                        raise excp

                newdict = copy.deepcopy(currdict)

                self._multilevelbuffer = newdict
                matches = self.setmultiworker(newargs, self._multilevelbuffer)

                if not matches:
                    sys.stderr.write("Property not found in selection '%s', " \
                                "skipping '%s'\n" % (instance.type, outputline))
                else:
                    entrydict = None
                    entrymono = None

                    if float(iloversion) >= 2.10:
                        entrydict = currdict
                        entrymono = self.current_client.monolith

                    try:
                        if attributeregistry[instance.type]:
                            if not validation_manager.bios_validate(\
                                            newdict, \
                                            attributeregistry[instance.type], \
                                            selector, currdict=entrydict, \
                                            monolith=entrymono):
                                sys.stderr.write("Property is read-only" \
                                             " skipping '%s'\n" % selector)
                                continue
                    except Exception:
                        selector = newarg[-1]
                        newdictcopy = newdict
                        for i in range(len(newarg)):
                            for item in newdictcopy.iterkeys():
                                if newarg[i].lower() == item.lower():
                                    if not newarg[i].lower() == newarg[-1].lower():
                                        newdictcopy = newdictcopy[item]
                        newdictcopy[type_string] = newdict[type_string]
                        currdictcopy[type_string] = currdict[type_string]
                        if not validation_manager.validate(newdictcopy, \
                                    selector=selector, currdict=currdictcopy, \
                                        monolith=entrymono, newarg=newarg, \
                                                                regloc=regloc):
                            sys.stderr.write("Property is " \
                                        "read-only skipping '%s'\n" % selector)
                            continue

                    validation_errors = validation_manager.get_errors()
                    if validation_errors and len(validation_errors) > 0:
                        raise ValidationError(validation_errors)

                    patch = jsonpatch.make_patch(currdict, newdict)

                    if patch:
                        for item in instance.patches:
                            if patch == item:
                                return
                            try:
                                if item[0]["path"] == patch.patch[0]["path"]:
                                    instance.patches.remove(item)
                            except Exception:
                                if item.patch[0]["path"] == \
                                                        patch.patch[0]["path"]:
                                    instance.patches.remove(item)

                        instance.patches.append(patch)
                        results.append({outputline:val})

                    if not patch:
                        for item in instance.patches:
                            try:
                                entry = item.patch[0]["path"].split('/')[1:]
                            except Exception:
                                entry = item[0]["path"].split('/')[1:]
                            if len(entry) == len(newarg):
                                check = 0
                                for index in range(len(entry)):
                                    if entry[index] == newarg[index]:
                                        check += 1
                                if check == len(newarg):
                                    instance.patches.remove(item)
                                    patchremoved = True
                                    nochangesmade = True

        if not nochangesmade:
            return "No entries found"
        if patchremoved:
            return "reverting"
        else:
            return results

    def setmultiworker(self, newargs, currdict, current=0):
        """ Helper function for multi level set function """
        found = False
        if not newargs[current] == newargs[-1]:
            for attr, val in currdict.iteritems():
                if attr.lower() == newargs[current].lower():
                    current += 1
                    found = self.setmultiworker(newargs, val, current)
                    continue
                else:
                    continue
        else:
            (name, value) = newargs[current].split('=', 1)
            for attr, val in currdict.iteritems():
                if attr.lower() == name.lower():
                    found = True
                    if value:
                        if value[0] == "[" and value[-1] == "]":
                            value = value[1:-1].split(',')
                            currdict[attr] = '"' + str(value) + '"'
                        else:
                            if value.lower() == "true" or value.lower() == "false":
                                value = value.lower() in ("yes", "true", "t", "1")
                            currdict[attr] = value
                    else:
                        currdict[attr] = value

        return found

    def info(self, selector=None, ignorelist=None, dumpjson=False, \
                                        autotest=False, newarg=None, \
                                        latestschema=False):
        """ Main function for info command """
        results = list()
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)
        (instances, attributeregistry) = self.get_selection(setenable=True)

        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            if self.get_save_helper(instance.resp.request.path, instances):
                continue
            bsmodel = None
            biosmode = False
            currdict = instance.resp.dict
            if selector:
                if newarg:
                    currdictcopy = currdict
                    for i in range(len(newarg)):
                        if isinstance(currdictcopy, dict):
                            for item in currdictcopy.iterkeys():
                                if newarg[i].lower() == item.lower():
                                    selector = item
                                    newarg[i] = item
                                    if not newarg[i].lower() == newarg[-1].lower():
                                        currdictcopy = currdictcopy[item]
                                        break
                        else:
                            break
                else:
                    for item in currdict.iterkeys():
                        if selector.lower() == item.lower():
                            selector = item
                            break
            if self.current_client.monolith._typestring in currdict:
                model, biosmode, bsmodel = self.get_model(currdict, \
                                    validation_manager, instance, iloversion,\
                                     attributeregistry, latestschema, newarg, autotest=autotest)

            if not model and not bsmodel:
                if newarg:
                    sys.stderr.write("No data available for entry: '%s'\n" \
                                                        % "/".join(newarg))
                    if autotest:
                        return True
                else:
                    LOGGER.warn(u"Unable to locate registry model for " \
                                                        ":'%s'", selector)
                    continue

            if selector:
                if newarg:
                    currdict = currdictcopy
                jsonpath_expr = jsonpath_rw.parse(u'"%s"' % selector)
                matches = jsonpath_expr.find(currdict)

                if matches:
                    for match in matches:
                        json_pstr = u'/%s' % match.full_path
                        jsonpointer.JsonPointer(json_pstr)

                        for key in currdict:
                            matchpath = u'%s' % match.full_path
                            if not key.lower() == matchpath.lower():
                                continue

                            if biosmode:
                                found = model.get_validator_bios(key)
                                if not found and bsmodel:
                                    found = bsmodel.get_validator(key)
                            else:
                                found = model.get_validator(key)

                            if found:
                                if dumpjson:
                                    print found
                                elif autotest:
                                    return True
                                else:
                                    found.print_help(selector, out=sys.stdout)
                            else:
                                sys.stderr.write("No data available for entry:"\
                                                 " '%s'\n" \
                                    % ("/".join(newarg) if newarg else selector))
                else:
                    sys.stderr.write("Entry '%s' not found in current" \
                                     " selection\n" \
                                    % ("/".join(newarg) if newarg else selector))

                results.append("Success")
            else:
                for key in currdict:
                    if key not in ignorelist:
                        results.append(key)

        return results

    def getbiosfamilyandversion(self):
        """ Function that returns the current bios family """
        (founddir, entrytype) = \
                        self.check_types_version(self.current_client.monolith)

        if founddir:
            self.check_types_exists(entrytype, "ComputerSystem.", \
                                self.current_client.monolith, skipcrawl=True)

        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    if "computersystem." in instance.type.lower():
                        try:
                            if instance.resp.obj["Bios"]["Current"]:
                                oemjson = instance.resp.obj["Bios"]["Current"]
                                parts = oemjson["VersionString"].split(" ")
                                return (parts[0], parts[1][1:])
                        except Exception:
                            pass

        return (None, None)

    def getiloversion(self, skipschemas=False):
        """ Function that returns the current bios family """
        iloversion = None

        results = self.get_handler(hpsdk.rest.v1.ROOT_ENDPOINT, silent=True, \
                                                            service=True)

        try:
            if results.dict["Oem"]["Hp"]["Manager"]:
                oemjson = results.dict["Oem"]["Hp"]["Manager"]
                iloversion = oemjson[0]["ManagerFirmwareVersion"]
        except Exception:
            pass

        if not skipschemas:
            if iloversion and not float(iloversion) < 2.10:
                self.verifyschemasdownloaded(self.current_client.monolith)

        return iloversion

    def status(self):
        """ Main function for status command """
        iloversion = self.getiloversion()
        validation_manager = self.get_validation_manager(iloversion)

        finalresults = list()
        monolith = self.current_client.monolith
        (_, attributeregistry) = self.get_selection(setenable=True)

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    results = list()

                    if instance.patches and len(instance.patches) > 0:
                        if isinstance(instance.patches[0], list):
                            results.extend(instance.patches)
                        else:
                            if instance.patches[0]:
                                for item in instance.patches:
                                    results.extend(item)

                    currdict = instance.resp.dict

                    itemholder = list()
                    for mainitem in results:
                        item = copy.deepcopy(mainitem)
                        regfound = None

                        try:
                            if attributeregistry[instance.type]:
                                regfound = validation_manager.\
                                find_bios_registry(attributeregistry[instance.type])
                        except Exception:
                            pass

                        if regfound:
                            model, _, _ = self.get_model(currdict, validation_manager, \
                                               instance, iloversion, \
                                               attributeregistry)

                            if model:
                                try:
                                    validator = \
                                        model.get_validator_bios(item[0]["path"][1:])
                                except Exception:
                                    validator = \
                                            model.get_validator_bios(item["path"][1:])

                                if validator:
                                    try:
                                        if isinstance(validator, \
                                                hpsdk.ris.validation.PasswordValidator):
                                            item[0]["value"] = "******"
                                    except Exception:
                                        if isinstance(validator, \
                                                hpsdk.ris.validation.PasswordValidator):
                                            item["value"] = "******"
                        itemholder.append(item)

                    if itemholder:
                        finalresults.append({instance.type: itemholder})

        return finalresults

    def capture(self):
        """ Build and return the entire monolith """
        monolith = self.current_client.monolith
        monolith.load()
        return monolith

    def commitworkerfunc(self, patch):
        """ Helper function for the commit command """
        try:
            entries = patch.patch[0]["path"][1:].split("/")
        except Exception:
            entries = patch[0]["path"][1:].split("/")

        counter = 0
        results = dict()
        for item in reversed(entries):
            if counter == 0:
                boolfound = False
                try:
                    boolfound = isinstance(patch.patch[0]["value"], bool)
                except Exception:
                    boolfound = isinstance(patch[0]["value"], bool)

                if boolfound:
                    results = {item:patch.patch[0]["value"]}
                else:
                    try:
                        if patch.patch[0]["value"][0] == '"' and\
                                            patch.patch[0]["value"][-1] == '"':
                            results = {item:patch.patch[0]["value"][1:-1]}
                        else:
                            results = {item:patch.patch[0]["value"]}
                    except Exception:
                        if patch[0]["value"][0] == '"' and\
                                                patch[0]["value"][-1] == '"':
                            results = {item:patch[0]["value"][1:-1]}
                        else:
                            results = {item:patch[0]["value"]}

                counter += 1
            else:
                results = {item:results}

        return results

    def commit(self, out=sys.stdout, verbose=False):
        """ Main function for commit command """
        changesmade = False
        instances = self.get_commit_selection()
        if not instances or len(instances) == 0:
            raise NothingSelectedError()

        for instance in instances:
            skip = False
            try:
                if not "PATCH" in instance.resp._http_response.msg.headers[0]:
                    if verbose:
                        out.write(u'Skipping read-only path: %s\n' % \
                                 instance.resp.request.path)
                    skip = True
            except Exception:
                try:
                    for item in instance.resp._headers:
                        if item.keys()[0] == "allow":
                            if not "PATCH" in item.values()[0]:
                                if verbose:
                                    out.write(u'Skipping read-only path:'\
                                          ' %s\n' % instance.resp.request.path)
                                skip = True
                                break
                except Exception:
                    if not "PATCH" in instance.resp._headers["allow"]:
                        if verbose:
                            out.write(u'Skipping read-only path: %s\n' % \
                                     instance.resp.request.path)
                        skip = True

            if skip:
                continue

            currdict = dict()
            # apply patches to represent current edits
            for patch in instance.patches:
                try:
                    self.checkforetagchange(instance=instance)
                except Exception, excp:
                    raise excp
                if hasattr(patch, 'patch'):
                    if len(patch.patch):
                        if "/" in patch.patch[0]["path"][1:]:
                            newdict = self.commitworkerfunc(patch)
                            if newdict:
                                self.merge_dict(currdict, newdict)
                        else:
                            if isinstance(patch.patch[0]["value"], int):
                                currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                            elif not isinstance(patch.patch[0]["value"], bool):
                                if patch.patch[0]["value"]:
                                    if patch.patch[0]["value"][0] == '"' and\
                                        patch.patch[0]["value"][-1] == '"' and\
                                        len(patch.patch[0]["value"]) == 2:
                                        currdict[patch.patch[0]["path"][1:]] = \
                                                                            ''
                                    elif patch.patch[0]["value"][0] == '"' and\
                                        patch.patch[0]["value"][-1] == '"':
                                        line = patch.patch[0]["value"]\
                                                        [2:-2].replace("'", "")
                                        line = line.replace(", ", ",")
                                        currdict[patch.patch[0]["path"]\
                                                        [1:]] = line.split(',')
                                    else:
                                        currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                                else:
                                    currdict[patch.patch[0]["path"][1:]] = \
                                                        patch.patch[0]["value"]
                            else:
                                currdict[patch.patch[0]["path"][1:]] = \
                                                    patch.patch[0]["value"]
                else:
                    if "/" in patch[0]["path"][1:]:
                        newdict = self.commitworkerfunc(patch)
                        if newdict:
                            self.merge_dict(currdict, newdict)
                    else:
                        if isinstance(patch[0]["value"], int):
                            currdict[patch[0]["path"][1:]] = \
                                                            patch[0]["value"]
                        elif not isinstance(patch[0]["value"], bool):
                            if patch[0]["value"]:
                                if patch[0]["value"][0] == '"' and\
                                            patch[0]["value"][-1] == '"' and \
                                            len(patch[0]["value"]) == 2:
                                    currdict[patch[0]["path"][1:]] = \
                                                            ''
                                elif patch[0]["value"][0] == '"' and\
                                                patch[0]["value"][-1] == '"':
                                    currdict[patch[0]["path"][1:]] = \
                                            patch[0]["value"][2:-2].split(',')
                                else:
                                    currdict[patch[0]["path"][1:]] = \
                                                            patch[0]["value"]
                            else:
                                currdict[patch[0]["path"][1:]] = \
                                                            patch[0]["value"]
                        else:
                            currdict[patch[0]["path"][1:]] = patch[0]["value"]

            if currdict:
                changesmade = True
                if verbose:
                    out.write(u'Changes made to path: %s\n' % \
                             instance.resp.request.path)

                put_path = instance.resp.request.path
                results = self.current_client.set(put_path, body=currdict, \
                          optionalpassword=self.current_client.bios_password)

                (base_messages, ilo_messages, hpcommon_messages, \
                                iloevent_messages) = self.get_error_messages()
                self.invalid_return_handler(results, ilo_messages, \
                                            base_messages, iloevent_messages,\
                                            hpcommon_messages)

                if not results.status == 200:
                    raise FailureDuringCommitError("Failed to commit with " \
                                           "iLO error code %d" % results.status)
        return changesmade

    def merge_dict(self, currdict, newdict):
        """ helper finction to merge dict """
        for k, itemv2 in newdict.items():
            itemv1 = currdict.get(k)
            if isinstance(itemv1, Mapping) and\
                 isinstance(itemv2, Mapping):
                self.merge_dict(itemv1, itemv2)
            else:
                currdict[k] = itemv2

    def get_error_messages(self):
        """ handler of error messages from ilo """
        try:
            iloversion = self.getiloversion()
            validation_manager = self.get_validation_manager(iloversion)

            regfound = validation_manager.find_registry("Base")

            if self.current_client.monolith.is_redfish and regfound:
                regfound = self.get_handler(regfound[u'@odata.id'], \
                    verbose=False,service=True,silent=True).obj
                regfound = RepoRegistryEntry(regfound)

            if not regfound:
                LOGGER.warn(u"Unable to locate registry for '%s'", "Base")
                raise
            elif float(iloversion) >= 2.10:
                try:
                    self.check_type_and_download(\
                                     self.current_client.monolith, \
                                    regfound.Location[0]["Uri"]["extref"], \
                                    skipcrawl=True, loadtype='ref')
                except Exception, excp:
                    raise excp

            validation_manager._base_messages = \
                                regfound.get_registry_model(skipcommit=True, \
                                        currdict={"Type": "Base"}, \
                                        monolith=self.current_client.monolith, \
                                        searchtype="MessageRegistry.")

            regfound = validation_manager.find_registry("iLO")
            
            if self.current_client.monolith.is_redfish and regfound:
                regfound = self.get_handler(regfound[u'@odata.id'], \
                    verbose=False,service=True,silent=True).obj
                regfound = RepoRegistryEntry(regfound)

            if not regfound:
                LOGGER.warn(u"Unable to locate registry for '%s'", "iLO")
                raise
            elif float(iloversion) >= 2.10:
                try:
                    self.check_type_and_download(\
                                     self.current_client.monolith, \
                                    regfound.Location[0]["Uri"]["extref"], \
                                    skipcrawl=True, loadtype='ref')
                except Exception, excp:
                    raise excp

            validation_manager._ilo_messages = \
                                regfound.get_registry_model(skipcommit=True, \
                                currdict={"Type": "iLO"}, \
                                monolith=self.current_client.monolith, \
                                searchtype="MessageRegistry.")

            regfound = validation_manager.find_registry("HpCommon")
            
            if self.current_client.monolith.is_redfish and regfound:
                regfound = self.get_handler(regfound[u'@odata.id'], \
                    verbose=False,service=True,silent=True).obj
                regfound = RepoRegistryEntry(regfound)

            if not regfound:
                LOGGER.warn(u"Unable to locate registry for '%s'", "HpCommon")
                raise
            elif float(iloversion) >= 2.10:
                try:
                    self.check_type_and_download(\
                                     self.current_client.monolith, \
                                    regfound.Location[0]["Uri"]["extref"], \
                                    skipcrawl=True, loadtype='ref')
                except Exception, excp:
                    raise excp

            validation_manager._hpcommon_messages = \
                                regfound.get_registry_model(skipcommit=True, \
                                currdict={"Type": "HpCommon"}, \
                                monolith=self.current_client.monolith, \
                                searchtype="MessageRegistry.")

            regfound = validation_manager.find_registry("iLOEvents")

            if self.current_client.monolith.is_redfish and regfound:
                regfound = self.get_handler(regfound[u'@odata.id'], \
                    verbose=False,service=True,silent=True).obj
                regfound = RepoRegistryEntry(regfound)

            if not regfound:
                LOGGER.warn(u"Unable to locate registry for '%s'", "iLOEvents")
                raise
            elif float(iloversion) >= 2.10:
                try:
                    self.check_type_and_download(\
                                     self.current_client.monolith, \
                                    regfound.Location[0]["Uri"]["extref"], \
                                    skipcrawl=True, loadtype='ref')
                except Exception, excp:
                    raise excp

            validation_manager._iloevents_messages = \
                                regfound.get_registry_model(skipcommit=True, \
                                currdict={"Type": "iLOEvents"}, \
                                monolith=self.current_client.monolith, \
                                searchtype="MessageRegistry.")

            return (validation_manager._base_messages, \
                    validation_manager._ilo_messages, \
                    validation_manager._hpcommon_messages,\
                    validation_manager._iloevents_messages)
        except Exception, excp:
            return (None, None, None, None)

    def patch_handler(self, put_path, body, optionalpassword=None, \
                            verbose=False, providerheader=None, service=False,\
                            url=None, sessionid=None):
        """main worker function for raw patch command"""
        ilo_messages = None
        base_messages = None
        iloevent_messages = None
        hpcommon_messages = None
        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).set(put_path,\
                                body=body, optionalpassword=optionalpassword,\
                                            providerheader=providerheader)
        else:
            results = self.current_client.set(put_path, body=body, \
                                          optionalpassword=optionalpassword, \
                                          providerheader=providerheader)

        if not service:
            (base_messages, ilo_messages, hpcommon_messages, \
                                iloevent_messages) = self.get_error_messages()
        self.invalid_return_handler(results, ilo_messages, \
                                            base_messages, iloevent_messages,\
                                            hpcommon_messages, verbose=verbose)

    def get_handler(self, put_path, silent=False, verbose=False, service=False,\
                                                 url=None, sessionid=None):
        """main worker function for raw get command"""
        ilo_messages = None
        base_messages = None
        iloevent_messages = None
        hpcommon_messages = None

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).get(put_path)
        else:
            results = self.current_client.get(put_path)

        if not silent and not service:
            (base_messages, ilo_messages, hpcommon_messages,
             iloevent_messages) = self.get_error_messages()

        if not silent:
            self.invalid_return_handler(results, ilo_messages, \
                                            base_messages, iloevent_messages,\
                                            hpcommon_messages, verbose=verbose)

        if results.status == 200:
            return results
        else:
            return None

    def post_handler(self, put_path, body, verbose=False, providerheader=None,\
                                        service=False, url=None, sessionid=None):
        """main worker function for raw post command"""
        ilo_messages = None
        base_messages = None
        iloevent_messages = None
        hpcommon_messages = None

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).toolpost(put_path,\
                                        body=body, providerheader=providerheader)
        else:
            results = self.current_client.toolpost(put_path, body=body, \
                                                providerheader=providerheader)

        if not service:
            (base_messages, ilo_messages, hpcommon_messages, \
                                iloevent_messages) = self.get_error_messages()
        self.invalid_return_handler(results, ilo_messages, \
                                            base_messages, iloevent_messages,\
                                            hpcommon_messages, verbose=verbose)

    def put_handler(self, put_path, body, optionalpassword=None, \
                            verbose=False, providerheader=None, service=False,\
                            url=None, sessionid=None):
        """main worker function for raw put command"""
        ilo_messages = None
        base_messages = None
        iloevent_messages = None
        hpcommon_messages = None

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).toolput(put_path,\
                                body=body, optionalpassword=optionalpassword, \
                                providerheader=providerheader)
        else:
            results = self.current_client.toolput(put_path, body=body, \
                                          optionalpassword=optionalpassword, \
                                          providerheader=providerheader)

        if not service:
            (base_messages, ilo_messages, hpcommon_messages, \
                                iloevent_messages) = self.get_error_messages()
        self.invalid_return_handler(results, ilo_messages, \
                                            base_messages, iloevent_messages,\
                                            hpcommon_messages, verbose=verbose)

    def delete_handler(self, put_path, verbose=False, providerheader=None,\
                                                service=False, url=None, \
                                                sessionid=None):
        """main worker function for raw delete command"""
        ilo_messages = None
        base_messages = None
        iloevent_messages = None
        hpcommon_messages = None

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).tooldelete(put_path,\
                                         providerheader=providerheader)
        else:
            results = self.current_client.tooldelete(put_path, \
                                                 providerheader=providerheader)

        if not service:
            (base_messages, ilo_messages, hpcommon_messages, \
                                iloevent_messages) = self.get_error_messages()
        self.invalid_return_handler(results, ilo_messages, \
                                            base_messages, iloevent_messages,\
                                            hpcommon_messages, verbose=verbose)
        return results

    def head_handler(self, put_path, verbose=False, service=False, url=None,\
                                                                sessionid=None):
        """main worker function for raw head command"""
        ilo_messages = None
        base_messages = None
        iloevent_messages = None
        hpcommon_messages = None

        if sessionid:
            results = RmcClient(url=url, sessionkey=sessionid).get(put_path)
        else:
            results = self.current_client.get(put_path)

        if not service:
            (base_messages, ilo_messages, hpcommon_messages, \
                                iloevent_messages) = self.get_error_messages()
        self.invalid_return_handler(results, ilo_messages, \
                                            base_messages, iloevent_messages,\
                                            hpcommon_messages, verbose=verbose)

        if results.status == 200:
            return results
        else:
            return None

    _QUERY_PATTERN = re.compile(r'(?P<instance>[\w\.]+)(:(?P<xpath>.*))?')
    def _parse_query(self, querystr):
        """ parse query and return as a dict
            TODO probably need to move this into its own class if it gets too
            complicated """
        qmatch = RmcApp._QUERY_PATTERN.search(querystr)
        if not qmatch:
            raise InvalidSelectionError(u"Unable to locate instance for '%s'" %\
                                                                    querystr)

        qgroups = qmatch.groupdict()

        return dict(instance=qgroups[u'instance'],
                    xpath=qgroups.get(u'xpath', None))

    def invalid_return_handler(self, results, ilomessages=None, \
                                            basemessages=None, \
                                            hpcommonmessages=None, \
                                            iloeventsmessages=None,\
                                            verbose=False):
        """main worker function for handling all error messages fro ilo"""
        try:
            contents = results.dict["Messages"][0]["MessageID"].split('.')
        except Exception:
            if results.status == 200:
                if verbose:
                    sys.stdout.write(u"[200] The operation completed " \
                                                            "successfully.\n")
                else:
                    sys.stdout.write(u"The operation completed successfully.\n")
            else:
                sys.stdout.write(u"[%d] No message returned by iLO.\n" % \
                                                                results.status)

            return

        if results.status == 401:
            raise SessionExpired()
        elif results.status == 403:
            raise IdTokenError()
        elif ilomessages and basemessages and hpcommonmessages and iloeventsmessages:
            if contents[0] == "Base":
                try:
                    if basemessages[contents[-1]]["NumberOfArgs"] == 0:
                        output = basemessages[contents[-1]]["Message"]
                    else:
                        output = basemessages[contents[-1]]["Description"]

                    if verbose:
                        sys.stdout.write(u"[%d] %s\n" % (results.status, \
                                                                        output))
                    else:
                        sys.stdout.write(u"%s\n" % output)
                except Exception:
                    pass
            elif contents[0] == "iLO":
                try:
                    if ilomessages[contents[-1]]["NumberOfArgs"] == 0:
                        output = ilomessages[contents[-1]]["Message"]
                    else:
                        output = ilomessages[contents[-1]]["Description"]

                    if verbose:
                        sys.stdout.write(u"[%d] %s\n" % (results.status, \
                                                                        output))
                    else:
                        sys.stdout.write(u"%s\n" % output)
                except Exception:
                    pass
            elif contents[0] == "HpCommon":
                try:
                    if hpcommonmessages[contents[-1]]["NumberOfArgs"] == 0:
                        output = hpcommonmessages[contents[-1]]["Message"]
                    else:
                        output = hpcommonmessages[contents[-1]]["Description"]

                    if verbose:
                        sys.stdout.write(u"[%d] %s\n" % (results.status, \
                                                                        output))
                    else:
                        sys.stdout.write(u"%s\n" % output)
                except Exception:
                    pass
            elif contents[0] == "iLOEvents":
                try:
                    if iloeventsmessages[contents[-1]]["NumberOfArgs"] == 0:
                        output = iloeventsmessages[contents[-1]]["Message"]
                    else:
                        output = iloeventsmessages[contents[-1]]["Description"]

                    if verbose:
                        sys.stdout.write(u"[%d] %s\n" % (results.status, \
                                                                        output))
                    else:
                        sys.stdout.write(u"%s\n" % output)
                except Exception:
                    pass
        else:
            if results.status == 200:
                if verbose:
                    sys.stdout.write(u"[200] The operation completed " \
                                                            "successfully.\n")
                else:
                    sys.stdout.write(u"The operation completed successfully.\n")
            else:
                sys.stdout.write(u"[%d] No message returned by iLO.\n" % \
                                                                results.status)

    def select(self, query, sel=None, val=None):
        """ Main function for select command """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError(u"Unable to locate instance " \
                                                "for '%s'" % query)
                else:
                    query = query[0]

            if val:
                if (str(val)[0] == str(val)[-1]) and str(val).endswith(("'", '"')):
                    val = val[1:-1]
            selection = self.get_selection(selector=query, sel=sel, val=val)
            if selection and len(selection) > 0:
                self.current_client.selector = query
                if not sel == None and not val == None:
                    self.current_client.filter_attr = sel
                    self.current_client.filter_value = val
                else:
                    self.current_client.filter_attr = None
                    self.current_client.filter_value = None
                self.save()
                return selection

        if not sel == None and not val == None:
            raise InstanceNotFoundError(u"Unable to locate instance for" \
                                " '%s' and filter '%s=%s'" % (query, sel, val))
        else:
            raise InstanceNotFoundError(u"Unable to locate instance for" \
                                        " '%s'" % query)

    def filter(self, query, sel, val):
        """ Main function for filter command """
        if query:
            if isinstance(query, list):
                if len(query) == 0:
                    raise InstanceNotFoundError(u"Unable to locate instance " \
                                                "for '%s'" % query)
                else:
                    query = query[0]

            selection = self.get_selection(selector=query, sel=sel, val=val)
            if selection and len(selection) > 0:
                self.current_client.selector = query
                self.current_client.filter_attr = sel
                self.current_client.filter_value = val
                self.save()

            return selection

    def types(self, fulltypes=False):
        """ Main function for types command """
        instances = list()
        monolith = self.current_client.monolith

        (founddir, entrytype) = self.check_types_version(monolith)

        if not founddir:
            for ristype in monolith.types:
                if u'Instances' in monolith.types[ristype]:
                    for instance in monolith.types[ristype][u'Instances']:
                        instances.append(instance.type)
        else:
            if u'Instances' in monolith.types[entrytype]:
                for instance in monolith.types[entrytype][u'Instances']:
                    for item in instance.resp.dict["Instances"]:
                        if item and instance._typestring in item.keys() and not \
                                u'ExtendedError' in item[instance._typestring]:
                            if not fulltypes and instance._typestring == u'@odata.type':
                                    t = item[u"@odata.type"].split('#')
                                    t = t[-1].split('.')[:-1]
                                    t = '.'.join(t)
                                    instances.append(t)
                            elif item:
                                instances.append(item[instance._typestring])

        return instances

    def gettypeswithetag(self):
        """ supporting function for set and commit command """
        instancepath = dict()
        instances = dict()
        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    instancepath[instance.type] = instance.resp.request.path
                    templist = instance.resp.getheaders()

                    tempindex = [x[0] for x in templist].index('etag')
                    instances[instance.type] = templist[tempindex][1]

        return [instances, instancepath]

    def reloadmonolith(self, path=None):
        """ Helper function to reload new data into monolith """
        if path:
            self.current_client.monolith.reload = True
            self.current_client.monolith.load(path=path, skipinit=True,\
                                              skipcrawl=True)
            self.current_client.monolith.reload = False
            return True
        else:
            return False

    def checkforetagchange(self, instance=None):
        """ Function to check the status of the etag """
        if instance:
            (oldtag, paths) = self.gettypeswithetag()
            self.reloadmonolith(paths[instance.type])
            (newtag, paths) = self.gettypeswithetag()
            if (oldtag[instance.type] != newtag[instance.type]) and \
                                        not u'HpiLODateTime.' in instance.type:
                sys.stdout.write("The property you are trying to change "\
                                 "has been updated. Please check entry again "\
                                 " before manipulating it\n")
                raise ValueChangedError()

    def verifyschemasdownloaded(self, monolith):
        """ function to verify that the schema has been downloaded """
        schemasfound = False
        registriesfound = False
        if monolith.is_redfish:
            schemaid = "/redfish/v1/schemas/"
            regid = "/redfish/v1/registries/"
        else:
            schemaid = "/rest/v1/schemas"
            regid = "/rest/v1/registries"

        for itemtype in monolith.types:
            if itemtype.startswith("Collection.") and \
                                    u'Instances' in monolith.types[itemtype]:
                for instance in monolith.types[itemtype][u'Instances']:
                    if instance.resp.request.path.lower() == schemaid:
                        schemasfound = True
                    elif instance.resp.request.path.lower() == \
                                                        regid:
                        registriesfound = True

        if not schemasfound:
            self.check_type_and_download(monolith, schemaid, skipcrawl=True)

        if not registriesfound:
            self.check_type_and_download(monolith, regid, skipcrawl=True)

    def check_types_version(self, monolith):
        """ check the types version """
        for ristype in monolith.types:
            if "HpiLOResourceDirectory.".lower() in ristype.lower():
                return (True, ristype)

        return (False, None)

    def check_type_and_download(self, monolith, foundhref, skipcrawl=False, \
                                                            loadtype='href'):
        """ check if type exist and download """
        found = False
        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    if foundhref == instance.resp.request.path:
                        found = True
                        break
                    elif foundhref == instance.resp.request.path + '/':
                        found = True
                        break

                if found:
                    break

        if not found:
            monolith.load(path=foundhref, skipinit=True, skipcrawl=skipcrawl, \
                                            includelogs=True, loadtype=loadtype)

    def check_types_exists(self, entrytype, currtype, monolith, skipcrawl=False):
        """ check if type exists in current monolith """
        if u'Instances' in monolith.types[entrytype]:
            for instance in monolith.types[entrytype][u'Instances']:
                for item in instance.resp.dict["Instances"]:
                    if monolith._typestring in item.keys() and currtype.lower() \
                                    in item[monolith._typestring].lower():
                        self.check_type_and_download(monolith, \
                            item[monolith._hrefstring], skipcrawl=skipcrawl)
                    elif currtype == '"*"':
                        self.check_type_and_download(monolith, \
                            item[monolith._hrefstring], skipcrawl=skipcrawl)


    def get_selection(self, selector=None, setenable=False, sel=None, val=None):
        """ Special main function for set/filter with select command """
        if not sel and not val:
            (sel, val) = self.get_filter_settings()

        attributeregistryfound = dict()
        monolith = self.current_client.monolith

        if selector:
            (founddir, entrytype) = self.check_types_version(monolith)
            if founddir:
                skipcrawl = True
                if selector.lower().startswith("log"):
                    skipcrawl = False
                    sys.stderr.write("Full data retrieval enabled. You may" \
                                     " experience longer download times.\n")

                self.check_types_exists(entrytype, selector, monolith, \
                                                            skipcrawl=skipcrawl)

        instances = list()
        if not selector:
            selector = self.current_client.selector

        if not selector:
            if setenable:
                return instances, attributeregistryfound
            else:
                return instances

        xpath = None
        odata = ''
        if not selector == '"*"':
            qvars = self._parse_query(selector)
            qinstance = qvars[u'instance']
            xpath = qvars[u'xpath']
        else:
            qinstance = selector

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    try:
                        odata = instance.resp.dict[u'@odata.type'].lower()
                    except Exception:
                        odata = ''
                    if instance.type.lower().startswith(qinstance.lower()) \
                                            or qinstance == '"*"' or \
                                            qinstance.lower() in odata:
                        if setenable:
                            try:
                                if instance.resp.obj["AttributeRegistry"]:
                                    attributeregistryfound[instance.type] = \
                                    instance.resp.obj["AttributeRegistry"]
                            except Exception:
                                pass

                            if self.get_save_helper(instance.resp.request.path, \
                                    monolith.types[ristype][u'Instances']):
                                continue

                        if not sel == None and not val == None:
                            currdict = instance.resp.dict
                            try:
                                if not "/" in sel:
                                    if "*" == val[-1]:
                                        if not val[:-1] in str(currdict[sel]):
                                            continue
                                    else:
                                        if not str(currdict[sel]).startswith(val):
                                            continue
                                else:
                                    newargs = sel.split("/")
                                    content = copy.deepcopy(currdict)
                                    if self.filterworkerfunction(workdict=\
                                            content, sel=sel, val=val, newargs\
                                                        =newargs, loopcount=0):
                                        instances.append(instance)
                                    continue
                            except Exception:
                                continue

                        if xpath:
                            raise RuntimeError(u"Not implemented")
                        else:
                            instances.append(instance)

        if setenable:
            return instances, attributeregistryfound
        else:
            return instances
    def filterworkerfunction(self, workdict=None, sel=None, val=None, \
                                                    newargs=None, loopcount=0):
        """ Helper function for filter application """
        if workdict and sel and val and newargs:
            if isinstance(workdict, list):
                for item in workdict:
                    if self.filterworkerfunction(workdict=item, sel=sel, \
                                 val=val, newargs=newargs, loopcount=loopcount):
                        return True

                return False

            keys = workdict.keys()
            keyslow = [x.lower() for x in keys]

            if newargs[loopcount].lower() in keyslow:
                if loopcount == (len(newargs) - 1):
                    if val == str(workdict[newargs[loopcount]]):
                        return True

                    return False

                if not (isinstance(workdict[newargs[loopcount]], list) or \
                    isinstance(workdict[newargs[loopcount]], dict)):
                    return False

                workdict = workdict[newargs[loopcount]]
                loopcount += 1

                if self.filterworkerfunction(workdict=workdict, sel=sel, \
                                             val=val, newargs=newargs, \
                                             loopcount=loopcount):
                    return True

        return False

    def get_commit_selection(self):
        """ Special main function for commit command"""
        instances = list()
        monolith = self.current_client.monolith

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    instances.append(instance)

        return instances

    def get_save_header(self, selector=None):
        """ Special function for save file headers """
        monolith = self.current_client.monolith

        instances = OrderedDict()

        if not selector:
            selector = self.current_client.selector

        if not selector:
            return instances

        instances["Comments"] = OrderedDict()

        (founddir, entrytype) = \
                        self.check_types_version(self.current_client.monolith)

        if founddir:
            self.check_types_exists(entrytype, "ComputerSystem.", \
                                self.current_client.monolith, skipcrawl=True)

        for ristype in monolith.types:
            if u'Instances' in monolith.types[ristype]:
                for instance in monolith.types[ristype][u'Instances']:
                    if "computersystem." in instance.type.lower():
                        try:
                            if \
                            instance.resp.obj["Manufacturer"]:
                                instances["Comments"]["Manufacturer"] = \
                                            instance.resp.obj["Manufacturer"]

                            if \
                            instance.resp.obj["Model"]:
                                instances["Comments"]["Model"] = \
                                                    instance.resp.obj["Model"]

                            if \
                            instance.resp.obj["Oem"]["Hp"]["Bios"]["Current"]:
                                oemjson = instance.resp.obj["Oem"]["Hp"]\
                                                            ["Bios"]["Current"]
                                instances["Comments"]["BIOSFamily"] = \
                                                            oemjson["Family"]
                                instances["Comments"]["BIOSDate"] = \
                                                                oemjson["Date"]
                        except Exception:
                            pass

        return instances

    def get_selector(self):
        """ Helper function to return current select option """
        if self.current_client:
            if self.current_client.selector:
                return self.current_client.selector

        return None

    def get_filter_settings(self):
        """ Helper function to return current select option """
        if self.current_client:
            if not self.current_client.filter_attr == None and not\
                                    self.current_client.filter_value == None:
                return (self.current_client.filter_attr,
                        self.current_client.filter_value)

        return (None, None)

    def erase_filter_settings(self):
        """ Helper function to return current select option """
        if self.current_client:
            if not self.current_client.filter_attr == None or \
                                not self.current_client.filter_value == None:
                self.current_client.filter_attr = None
                self.current_client.filter_value = None

    def update_bios_password(self, value):
        """ Helper function to return current select option """
        if self.current_client:
            self.current_client.bios_password = value

    def get_validation_manager(self, iloversion):
        """ get validation manager helper """
        monolith = None

        if float(iloversion) >= 2.10:
            monolith = self.current_client.monolith

        (romfamily, biosversion) = self.getbiosfamilyandversion()
        validation_manager = ValidationManager(\
                            local_path=self._config.get_schemadir(), \
                            bios_local_path=self._config.get_biosschemadir(), \
                            romfamily=romfamily, biosversion=biosversion, \
                            iloversion=iloversion, monolith=monolith)

        return validation_manager
    def get_model(self, currdict, validation_manager, instance, \
                  iloversion, attributeregistry, latestschema=None, \
                  newarg=None, autotest=False):
        """ Returns the model for the current instance's schema/registry """
        biosschemafound = None
        bsmodel = None
        biosmode = False
        type_str = self.current_client.monolith._typestring

        if latestschema:
            schematype = currdict[type_str].split('.')[0] + '.'
            reglist = validation_manager._classes_registry[0][u'Items']

            for item in validation_manager._classes[0][u'Items']:
                if item and item[u'Schema'].startswith(schematype):
                    schematype = item[u'Schema']
                    break

            regs = [x[u'Schema'] for x in reglist if x[u'Schema']\
                    .lower().startswith('hpbiosattributeregistry')]
            i = [reglist.index(x) for x in reglist if x[u'Schema']\
                 .lower().startswith('hpbiosattributeregistry')]
            regs = zip(regs, i)

            for item in sorted(regs, reverse=True):
                extref = self.get_handler(reglist[item[1]][u'Location'][0]\
                            ["Uri"]["extref"], \
                            verbose=False, service=True, silent=True)
                if extref:
                    regtype = item[0]
                    break

            if autotest:
                try:
                    if not regtype == attributeregistry[instance.type]:
                        sys.stderr.write("Using latest registry.\nFound: %s\n" \
                                         "Using: %s\n" % \
                                            (attributeregistry[instance.type],\
                                            regtype))
                except:
                    if not schematype == currdict[type_str]:
                        sys.stderr.write("Using latest schema.\nFound: %s\n" \
                                         "Using: %s\n" % \
                                            (currdict[type_str],\
                                            schematype))
        else:
            schematype = currdict[type_str]
            try:
                regtype = attributeregistry[instance.type]
            except Exception:
                pass
        try:
            if attributeregistry[instance.type]:
                regfound = validation_manager.\
                find_bios_registry(regtype)
                biosmode = True
                biosschemafound = \
                    validation_manager.find_schema(schematype)
                if self.current_client.monolith.is_redfish and biosschemafound:
                    regfound = self.get_handler(regfound[u'@odata.id'], \
                        verbose=False,service=True,silent=True).obj
                    regfound = RepoRegistryEntry(regfound)
        except:
            regfound = validation_manager.find_schema(schematype)
        if self.current_client.monolith.is_redfish and regfound:
            regfound = self.get_handler(regfound[u'@odata.id'], \
                verbose=False,service=True,silent=True).obj
            regfound = RepoRegistryEntry(regfound)
        if not regfound:
            LOGGER.warn(u"Unable to locate registry/schema for '%s'", \
                currdict[type_str])
            return None, None, None
        elif float(iloversion) >= 2.10:
            try:
                self.check_type_and_download(\
                                 self.current_client.monolith, \
                                regfound.Location[0]["Uri"]["extref"], \
                                skipcrawl=True, loadtype='ref')

                if biosschemafound:
                    self.check_type_and_download(\
                            self.current_client.monolith, \
                            biosschemafound.Location[0]["Uri"]\
                            ["extref"],skipcrawl=True, loadtype='ref')
            except Exception, excp:
                raise excp

        if biosmode:
            if float(iloversion) >= 2.10:
                model = regfound.get_registry_model_bios_version(\
                                currdict=currdict, \
                                monolith=self.current_client.monolith)

            if biosschemafound:
                bsmodel = biosschemafound.get_registry_model(\
                                currdict=currdict, \
                                monolith=self.current_client.monolith, \
                                latestschema=latestschema)
            if not biosschemafound and not model:
                model = regfound.get_registry_model_bios_version(\
                                                             currdict)
        else:
            if float(iloversion) >= 2.10:
                model = regfound.get_registry_model(\
                                currdict=currdict, \
                                monolith=self.current_client.monolith, \
                                newarg=newarg, latestschema=latestschema)
            else:
                model = regfound.get_registry_model(currdict)

        return model, biosmode, bsmodel
