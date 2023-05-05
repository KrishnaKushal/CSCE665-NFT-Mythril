import setuptools

setuptools.setup(
    name="nft_ownership_detector",
    version="0.0.1",
    author="Krishna Kushal",
    author_email="",
    description="NFT Onwership Vulnerability Detector",
    long_description="This module checks for NFT ownership vulnerabilities",
    long_description_content_type="text/markdown",
    packages=["nft_ownership_detector"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    # ===========================================
    # The entry_points field is used to register the plugin with mythril
    #
    # Right now we register only one plugin for the "mythril.plugins" entry point,
    # note that you can add multiple plugins.
    # ===========================================
    entry_points={
        "mythril.plugins": [
            "nft_ownership_detector = nft_ownership_detector:NFTOwnershipDetector",
        ],
    },
    python_requires=">=3.6",
)
