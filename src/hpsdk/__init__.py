"""HP python modules

This package contains the following modules:

cpq_package -- classes for working with HP SmartComponents

"""

__all__ = ['rest', 'ris', 'hpilo']
__version__ = "0.0.1"


from hpsdk.rest.v1 import rest_client
import logging
(logging.getLogger(__name__)).setLevel(logging.ERROR)

def hpsdk_logger():
    return logging.getLogger(__name__)
