from setuptools import setup

setup(
    name='python-krb5',
    version='0.0.0a',
    description='Pure Python Kerberos V5',
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
    ],
    author='Trax DevOps',
    author_email='devops@traxtech.com',
    url='https://github.com/TraxTechnologies/python-krb5',
    packages=['krb5'],
    install_requires=[
        'pyasn1',
        'PyCrypto',
    ],
    #tests_require=TestCmd.tests_require(),
    #cmdclass = {'test': TestCmd},
)
