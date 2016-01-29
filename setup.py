from setuptools import setup, find_packages


setup(name='python-proliant-sdk',
      version='0.0.1',
      description='Hewlett Packard Enterprise SDK',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 2.7',
          'Topic :: Communications'
      ],
      keywords='HP Enterprise',
      url='https://github.com/HewlettPackard/python-proliant-sdk',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpatch',
          'jsonpath_rw',
          'jsonpointer',
          'jsonschema',
          'simplejson',
          'urlparse2'
      ])
