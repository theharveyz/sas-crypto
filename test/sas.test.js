import chai from "chai";
import SAS from "../src/";
import fs from "fs";
import ursa from "ursa";
const assert = chai.assert;
chai.should();

const sas = new SAS();
const private_key = fs.readFileSync("./test/_fixture/private.pem");
const public_key = fs.readFileSync("./test/_fixture/public.pub");
const data = "hello anri!"

describe("anri test", () => {

    it("random hash aes key length should be 64", () => {
        let aes_key = sas._createRandomHash();
        assert.equal(aes_key.length, 64);
    });

    it("specify key", () => {
        let str = private_key.toString("utf8");
        str.should.be.a("string");
        assert(ursa.isPrivateKey(sas.key(str)._key), true);
    });

    it("private key encrypt, public key decrypt", () => {
        let encrypted_data = sas.key(private_key).encrypt(data);
        assert.equal(sas.key(public_key, 'public').decrypt(encrypted_data), data);
    });

    it("public key encrypt, private key decrypt", () => {
        let encrypted_data = sas.key(public_key, 'public').encrypt(data);
        assert.equal(sas.key(private_key, 'private').decrypt(encrypted_data), data);
    });
});

