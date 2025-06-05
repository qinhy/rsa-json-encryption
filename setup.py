from setuptools import setup

setup(
    name="rsa-json-encryption",
    version="0.1.0",
    py_modules=["rjson"],
    author="qinhy",
    description="RSA JSON Encryption with PEM Key Support",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/qinhy/rsa-json-encryption",
    license="MIT",
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)