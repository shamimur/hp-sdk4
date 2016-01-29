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
""" Shared types used in this module """

#---------Imports---------

import logging
import jsonpatch
from hpsdk.rest.v1_helper import JSONEncoder

#---------End of imports---------

#---------Debug logger---------

LOGGER = logging.getLogger(__name__)

#---------End of debug logger---------

class JSONEncoder(JSONEncoder):
    """
    Custom JSONEncoder that understands our types
    """
    def default(self, obj):
        """ Set defaults """
        if isinstance(obj, Dictable):
            return obj.to_dict()
        elif isinstance(obj, jsonpatch.JsonPatch):
            return obj.patch
        return super(JSONEncoder, self).default(obj)

class Dictable(object):
    """ A base class which adds the to_dict method used during json """\
                                                                """encoding. """
    def to_dict(self):
        """ Overridable funciton """
        raise RuntimeError("You must override this method in your derived" \
                           " class")
