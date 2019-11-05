from setuptools import setup, find_packages


with open('README.md') as f:
    long_description = ''.join(f.readlines())


setup(
    name='ghia_volekada',
    version='0.3',
    description='GitHub issues assignment tool',
    long_description=long_description,
    author='Adam Volek',
    author_email='volekada@fit.cvut.cz',
    license='Public Domain',
    keywords='git,github,issues,automation,assignment', # todo add some more
    url='https://github.com/czAdamV/GHIA',
    packages=find_packages(),
    package_data={'ghia': ['templates/*.html']},
    install_requires=['Flask', 'click', 'requests'],
    entry_points={
        'console_scripts': [
            'ghia = ghia:main',
        ],
    },
    classifiers=[
        'Intended Audience :: Developers',
        'License :: Public Domain',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.7',
        'Framework :: Flask',
        'Environment :: Console',
        'Environment :: Web Environment',
    ],
    zip_safe=False,
)