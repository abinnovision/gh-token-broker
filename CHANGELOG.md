# Changelog

## [0.6.0](https://github.com/abinnovision/gh-token-broker/compare/v0.5.0...v0.6.0) (2026-07-19)


### Features

* add typed resource identifiers (repo:, org:, enterprise:) ([#20](https://github.com/abinnovision/gh-token-broker/issues/20)) ([1bf21eb](https://github.com/abinnovision/gh-token-broker/commit/1bf21ebe448287497089ba21c8f200d962682328))
* **ci:** migrate to exchange-github-token action ([#21](https://github.com/abinnovision/gh-token-broker/issues/21)) ([c3b5392](https://github.com/abinnovision/gh-token-broker/commit/c3b539298a2dc9cb09c440711416c654443931d0))
* include app bot identity in token exchange response ([#23](https://github.com/abinnovision/gh-token-broker/issues/23)) ([f18f977](https://github.com/abinnovision/gh-token-broker/commit/f18f9777c66a594774a69d6d5a0c05cbcfa91bb7))

## [0.5.0](https://github.com/abinnovision/gh-token-broker/compare/v0.4.1...v0.5.0) (2026-07-19)


### Features

* adopt expanded golangci-lint config from oidc-token-cli ([#8](https://github.com/abinnovision/gh-token-broker/issues/8)) ([488e4a2](https://github.com/abinnovision/gh-token-broker/commit/488e4a255ae85f34bcf172971db510eb1c142378))
* align config structure ([#11](https://github.com/abinnovision/gh-token-broker/issues/11)) ([772be3d](https://github.com/abinnovision/gh-token-broker/commit/772be3d88ad9afd8c9f5a0233aae4d681fedfd89))
* generate config.schema.json from Go types and permission catalog ([#18](https://github.com/abinnovision/gh-token-broker/issues/18)) ([7b495eb](https://github.com/abinnovision/gh-token-broker/commit/7b495eb4d301e079ce0f17ada1b83d8455326fff))
* generate permission catalog from GitHub OpenAPI spec ([#13](https://github.com/abinnovision/gh-token-broker/issues/13)) ([97df60d](https://github.com/abinnovision/gh-token-broker/commit/97df60dd16320855665172c03973102cb003f6ad))
* remove non-OIDC endpoints, simplify to pure RFC 8693 token exchange ([#9](https://github.com/abinnovision/gh-token-broker/issues/9)) ([0aac7d4](https://github.com/abinnovision/gh-token-broker/commit/0aac7d4e3b07ce4a14a3ca5cd195824da3a9e14c))
* support $PORT and env-based config for serverless deploys ([#6](https://github.com/abinnovision/gh-token-broker/issues/6)) ([4eba92f](https://github.com/abinnovision/gh-token-broker/commit/4eba92f1601069174c4039805456aced2d37e8e6))
* validate GitHub App permissions at startup and mint time ([#10](https://github.com/abinnovision/gh-token-broker/issues/10)) ([ce23695](https://github.com/abinnovision/gh-token-broker/commit/ce23695e7e54b94a4d6b35759ca90b70a55cf3f5))
