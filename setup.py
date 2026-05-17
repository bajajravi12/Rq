from setuptools import setup, find_packages

setup(
    name="rqrv",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "aiohttp",
        "httpx[http2]",
        "dnspython",
        "tldextract",
        "ipwhois",
        "cryptography",
        "pyOpenSSL",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "rq=rqrv.main:main",
        ],
    },
)
