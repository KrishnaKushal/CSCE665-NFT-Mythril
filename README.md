# Mythril

## Installation and setup

```bash
$ docker build -t mythril/myth .
```

### nft ownership vulnerability plugin will be installed automatically while running above command.

## Usage Examples

Run with all vulnerabilities:

```
$ docker run -v $PWD/data:/data mythril/myth -v4 analyze /data/NftMarketplace.sol --solc-json /data/remapping.json
```

Run with Seller Address Verification vulnerability

```
$ docker run -v $PWD/data:/data mythril/myth -v4 analyze /data/NftMarketplace_1.sol --solc-json /data/remapping.json
```