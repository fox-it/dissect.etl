from setuptools import setup, find_packages

setup(
    name="dissect.etl",
    packages=list(map(lambda v: "dissect." + v, find_packages("dissect"))),
    package_data={"dissect.etl": ["manifests/xml/*.xml"]},
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
    ],
)
