# Changelog

## [1.5.1](https://github.com/awslabs/cognito-at-edge/tree/1.5.1) (2024-03-04)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.5.0...1.5.1)

**Fixed:**

- Add support for custom cognito redirect path [\#87](https://github.com/awslabs/cognito-at-edge/pull/87) ([fknittel](https://github.com/fknittel))

**Merged pull requests:**

- Bump @babel/traverse from 7.20.13 to 7.24.0 [\#91](https://github.com/awslabs/cognito-at-edge/pull/91) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump tough-cookie from 4.1.2 to 4.1.3 [\#90](https://github.com/awslabs/cognito-at-edge/pull/90) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore: update axios to 1.6.5 to resolve npm audit alarm [\#85](https://github.com/awslabs/cognito-at-edge/pull/85) ([elliotsegler](https://github.com/elliotsegler))

## [1.5.0](https://github.com/awslabs/cognito-at-edge/tree/1.5.0) (2023-07-24)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.4.0...1.5.0)

**Added:**

- Add additional handlers and CSRF protection [\#68](https://github.com/awslabs/cognito-at-edge/pull/68) ([vikas-reddy](https://github.com/vikas-reddy))

**Merged pull requests:**

- Improve types and type checks [\#71](https://github.com/awslabs/cognito-at-edge/pull/71) ([peternedap](https://github.com/peternedap))

## [1.4.0](https://github.com/awslabs/cognito-at-edge/tree/1.4.0) (2023-04-18)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.3.2...1.4.0)

**Added:**

- Use refetch token, if available [\#51](https://github.com/awslabs/cognito-at-edge/pull/51) ([maverick089](https://github.com/maverick089))

## [1.3.2](https://github.com/awslabs/cognito-at-edge/tree/1.3.2) (2023-02-20)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.3.1...1.3.2)

**Added:**

- Support SameSite cookie [\#50](https://github.com/awslabs/cognito-at-edge/pull/50) ([ckifer](https://github.com/ckifer))

**Fixed:**

- Unhandled error if cookies disabled [\#52](https://github.com/awslabs/cognito-at-edge/issues/52)
- Handle missing cookies in request [\#53](https://github.com/awslabs/cognito-at-edge/pull/53) ([foxbox-doug](https://github.com/foxbox-doug))

## [1.3.1](https://github.com/awslabs/cognito-at-edge/tree/1.3.1) (2022-12-05)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.3.0...1.3.1)

**Fixed:**

- Incorrect Regex of idToken With Subdomains [\#43](https://github.com/awslabs/cognito-at-edge/issues/43)

## [1.3.0](https://github.com/awslabs/cognito-at-edge/tree/1.3.0) (2022-11-22)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.2.2...1.3.0)

**Added:**

- feat: httpOnly param [\#41](https://github.com/awslabs/cognito-at-edge/pull/41) ([tsop14](https://github.com/tsop14))

## [1.2.2](https://github.com/awslabs/cognito-at-edge/tree/1.2.2) (2022-04-12)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.2.1...1.2.2)

**Fixed:**

- Fix type mismatch of the status code [\#35](https://github.com/awslabs/cognito-at-edge/pull/35) ([piotrekwitkowski](https://github.com/piotrekwitkowski))
- fix: update regex to account for idToken being last key value pair in cookie string [\#33](https://github.com/awslabs/cognito-at-edge/pull/33) ([timbakkum](https://github.com/timbakkum))

**Merged pull requests:**

- Update axios and aws-jwt-verify dependencies [\#30](https://github.com/awslabs/cognito-at-edge/pull/30) ([ottokruse](https://github.com/ottokruse))

## [1.2.1](https://github.com/awslabs/cognito-at-edge/tree/1.2.1) (2022-01-17)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.2.0...1.2.1)

**Fixed:**

- Add npmignore to include dist files in npm releases [\#28](https://github.com/awslabs/cognito-at-edge/pull/28) ([pedromgarcia](https://github.com/pedromgarcia))

## [1.2.0](https://github.com/awslabs/cognito-at-edge/tree/1.2.0) (2022-01-14)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.1.1...1.2.0)

**Added:**

- Add typescript support [\#26](https://github.com/awslabs/cognito-at-edge/pull/26) ([piotrekwitkowski](https://github.com/piotrekwitkowski))

**Closed issues:**

- Switch to typescript [\#20](https://github.com/awslabs/cognito-at-edge/issues/20)

## [1.1.1](https://github.com/awslabs/cognito-at-edge/tree/1.1.1) (2022-01-10)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.1.0...1.1.1)

**Fixed:**

- Double Decoding of the QueryParams [\#23](https://github.com/awslabs/cognito-at-edge/issues/23)
- Add Cache-Control headers to redirect responses [\#18](https://github.com/awslabs/cognito-at-edge/issues/18)
- Fix for double query params decoding [\#24](https://github.com/awslabs/cognito-at-edge/pull/24) ([akhudiakov97](https://github.com/akhudiakov97))
- Add cache-control & pragma headers to redirect responses [\#19](https://github.com/awslabs/cognito-at-edge/pull/19) ([ineale2](https://github.com/ineale2))

**Merged pull requests:**

- Use aws-jwt-verify to verify JSON Web Tokens [\#15](https://github.com/awslabs/cognito-at-edge/pull/15) ([ottokruse](https://github.com/ottokruse))

## [1.1.0](https://github.com/awslabs/cognito-at-edge/tree/1.1.0) (2021-10-05)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/1.0.0...1.1.0)

Merge PRs by external contributors to add support for new use cases

**Added:**

- added optional disableCookieDomain parameter [\#11](https://github.com/awslabs/cognito-at-edge/pull/11) ([jwwheeleriv](https://github.com/jwwheeleriv))
- add authentication to the fetch tokens from code [\#9](https://github.com/awslabs/cognito-at-edge/pull/9) ([yoavya](https://github.com/yoavya))

**Closed issues:**

- Cookie domain attribute should optionally be disabled [\#10](https://github.com/awslabs/cognito-at-edge/issues/10)
- Cognito client Id with secret [\#7](https://github.com/awslabs/cognito-at-edge/issues/7)

## [1.0.0](https://github.com/awslabs/cognito-at-edge/tree/1.0.0) (2021-06-28)

[Full Changelog](https://github.com/awslabs/cognito-at-edge/compare/9ad4d41623deafb8c217b9071fe2e63a4d4f30c7...1.0.0)

Initial open-source release of `cognito-at-edge`.

**Merged pull requests:**

- Update README and package.json and add a PR template [\#3](https://github.com/awslabs/cognito-at-edge/pull/3) ([jeandek](https://github.com/jeandek))
- Add unit test cases to achieve full coverage [\#2](https://github.com/awslabs/cognito-at-edge/pull/2) ([jeandek](https://github.com/jeandek))
- Readme updates [\#1](https://github.com/awslabs/cognito-at-edge/pull/1) ([jenirain](https://github.com/jenirain))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
