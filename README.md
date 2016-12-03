# sas-crypto
[![npm version](https://badge.fury.io/js/sas-crypto.svg)](https://badge.fury.io/js/sas-crypto)
[![CircleCI](https://circleci.com/gh/ZhangHarvey/sas-crypto.svg?style=svg)](https://circleci.com/gh/ZhangHarvey/sas-crypto)
[![codecov](https://codecov.io/gh/ZhangHarvey/sas-crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/ZhangHarvey/sas-crypto)

非对称与对称加密结合使用的加密工具。

## 特点
sas-crypto加密工具是对传统非对称加密算法（RSA）的一种优化。由于传统非对称加密算法会导致很高的资源消耗，且对要加密数据的长度也有一定的限制。

因此，sas-crypto将加密环节分为两个部分：1，数据部分采用AES对称加密方式，提高加密效率；2，对对称加密的秘钥进行非对称加密。通过这种方式，即保证了效率，又能不失非对称加密的安全性。并且对称加密的秘钥会随机产生。

## Quick start

- 私钥加密，公钥解密：
```javascript
import SAS from 'sas-crypto';

const encryptedData = new SAS().key(privateKey, 'private').encrypt('hello');

const decryptedData = new SAS().key(publickey, 'public').decrypt(encryptedData);
console.log(decryptedData);
// output: hello

```
- 公钥加密，私钥解密：
```javascript
import SAS from 'sas-crypto';

const encryptedData = new SAS().key(publickey, 'public').encrypt('hello');

const decryptedData = new SAS().key(privateKey, 'private').decrypt(encryptedData);
console.log(decryptedData);
// output: hello
```

**注意：**
* key方法，第二个参数默认为'private'
* privateKey/publicKey，可以为`string`|`Buffer`