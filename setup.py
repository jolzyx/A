from setuptools import setup, find_packages

meta = {}
with open("./src/authipy/version.py", encoding="utf-8") as f:
    exec(f.read(), meta)

setup(
    name="Authipy",
    version=meta["__version__"],
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "PyQt5>=5.15.0",
        "pyotp>=2.8.0",
        "pyperclip>=1.8.2",
        "PyQRCode>=1.2.1",
        "pypng>=0.20220715.0",
    ],
    entry_points={
        "console_scripts": [
            "authipy=authipy.main:main",
        ],
    },
    author='TanmoyTheBoT',
    description='2FA Authenticator',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/TanmoyTheBoT/Authipy',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
    test_suite='tests',
    tests_require=[
        'pytest>=7.0.0',
        'pytest-qt>=4.2.0',
        'pytest-cov>=4.1.0',
        'pytest-mock>=3.10.0',
        'pytest-xvfb>=2.0.0',
        'pytest-timeout>=2.1.0',
    ],
)