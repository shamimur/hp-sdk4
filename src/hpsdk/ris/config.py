import logging
import os
import re
import ConfigParser
logger = logging.getLogger(__name__)

VERSION = '1.0'


class AutoConfigParser(object):

    # properties starting with _ac__ are automatically
    # serialized to config file
    _config_pattern = re.compile(r'_ac__(?P<confkey>.*)')

    def __init__(self, filename=None):
        self._sectionname = 'globals'
        self._configfile = filename

    def _get_ac_keys(self):
        result = []
        for key in self.__dict__.keys():
            match = AutoConfigParser._config_pattern.search(key)
            if match:
                result.append(match.group('confkey'))
        return result

    def _get(self, key):
        ackey = '_ac__%s' % key.replace('-', '_')
        if ackey in self.__dict__:
            return self.__dict__[ackey]
        return None


    def _set(self, key, value):
        ackey = '_ac__%s' % key.replace('-', '_')
        if ackey in self.__dict__:
            self.__dict__[ackey] = value
        return None


    def load(self, filename=None):
        """
        load configuration settings from the file filename, if filename is None then the
        value from get_configfile() is used
        """
        fname = self.get_configfile()
        if filename is not None and len(filename) > 0:
            fname = filename

        if fname is None or not os.path.isfile(fname):
            return
        try:
            config = ConfigParser.RawConfigParser()
            config.read(fname)
            for key in self._get_ac_keys():
                configval = None
                try:
                    configval = config.get(self._sectionname, key)
                except ConfigParser.NoOptionError:
                    # also try with - instead of _
                    try:
                        configval = config.get(self._sectionname, key.replace('_', '-'))
                    except ConfigParser.NoOptionError:
                        pass

                if configval is not None and len(configval) > 0:
                    ackey = '_ac__%s' % key
                    self.__dict__[ackey] = configval

        except ConfigParser.NoOptionError:
            pass
        except ConfigParser.NoSectionError:
            pass


    def save(self, filename=None):
        """
        load configuration settings from the file filename, if filename is None then the
        value from get_configfile() is used
        """
        fname = self.get_configfile()
        if filename is not None and len(filename) > 0:
            fname = filename

        if fname is None or len(fname) == 0:
            return

        config = ConfigParser.RawConfigParser()
        try:
            config.add_section(self._sectionname)
        except ConfigParser.DuplicateSectionError:
            pass # ignored

        for key in self._get_ac_keys():
            ackey = '_ac__%s' % key
            config.set(self._sectionname, key, str(self.__dict__[ackey]))

        f = open(self._configfile, 'wb')
        config.write(f)
        f.close()

    def get_configfile(self):
        """ The current configuration file """
        return self._configfile
