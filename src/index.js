import ursa from 'ursa';
import crypto from 'crypto';

export default class SAS {

	constructor(symmetry, dilimiter) {
		this.symmetry = symmetry || 'aes-256-cbc';
		this.dilimiter = dilimiter || ".s.a.s.";
	}

	/**
   * @param {string|Buffer} key
   * @param {string} method
   */
	key(key, method = 'private') {
		this.rsakey = key instanceof Buffer ? key : typeof key == 'string' || typeof key == 'number' ? new Buffer(key) : null;
		if(method == 'private') {
			this.rsakey = ursa.createPrivateKey(this.rsakey);
		} else {
			this.rsakey = ursa.createPublicKey(this.rsakey);
		}
		return this;
	}

	/**
   * @param {string} data
   */
	encrypt(data) {
		if (!ursa.isKey(this.rsakey)) {
			throw new Error("Please specify the correct key!");
		}
		let aesKey = this.createRandomHash();
		const encryptedData = this.aesEncrypt(aesKey, data);
		// 加密aesKey
		aesKey = ursa.isPrivateKey(this.rsakey) ? this.privateRsaEncrypt(aesKey) : this.publicRsaEncrypt(aesKey);
		return aesKey + this.dilimiter + encryptedData;
	}

	/**
   * @param {string} encryptedData
   */
	decrypt(encryptedData) {
		if (!ursa.isKey(this.rsakey)) {
			throw new Error("Please specify the correct key!");
		}
		const data = encryptedData.split(this.dilimiter);
		if (data.length != 2) {
			throw new Error("The encrypted data is illegal!");
		}

		const aesKey = ursa.isPrivateKey(this.rsakey) ? this.privateRsaDecrypt(data[0]) : this.publicRsaDecrypt(data[0]);
		return this.aesDecrypt(aesKey, data[1]);
	}

	/**
   * 生成随机aes key
   */
	createRandomHash() {
		return crypto.randomBytes(32).toString('hex');
	}

  /**
   * aes对称加密
   */
	aesEncrypt(key, data) {
		const cip = crypto.createCipher(this.symmetry, key);
		let encryptedData = '';
		encryptedData += cip.update(data, 'utf8', 'base64');
		encryptedData += cip.final('base64');
		return encryptedData;
	}

  /**
   * aes对称解密
   */
	aesDecrypt(key, data) {
		const cip = crypto.createDecipher(this.symmetry, key);
		let decrypted_data = '';
		decrypted_data += cip.update(data, 'base64', 'utf8');
		decrypted_data += cip.final('utf8');
		return decrypted_data;
	}

	/**
   * 私钥加密
   */
	privateRsaEncrypt(data) {
		return this.rsakey.privateEncrypt(data, 'binary', 'base64');
	}

  /**
   * 公钥解密
   */
	publicRsaDecrypt(data) {
		return this.rsakey.publicDecrypt(data, 'base64', 'binary');
	}

	/**
   * 公钥加密
   */
	publicRsaEncrypt(data) {
		return this.rsakey.encrypt(data, 'binary', 'base64');
	}

  /**
   * 私钥解密
   */
	privateRsaDecrypt(data) {
		return this.rsakey.decrypt(data, 'base64', 'binary');
	}
};
