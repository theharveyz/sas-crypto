import chai from "chai";
import SAS from "../src";
import fs from "fs";
import ursa from "ursa";
const assert = chai.assert;
chai.should();

const sas = new SAS();
const privateKey = fs.readFileSync("./_fixture/private.pem");
const publicKey = fs.readFileSync("./_fixture/public.pub");
const data = "hello sas!"

describe("sas test", () => {

  it("random hash aes key length should be 64", () => {
    const aesKey = sas.createRandomHash();
    assert.equal(aesKey.length, 64);
  });

  it("specify key", () => {
    let str = privateKey.toString("utf8");
    str.should.be.a("string");
    assert(ursa.isPrivateKey(sas.key(str).rsakey), true);
  });

  it("private key encrypt, public key decrypt", () => {
    let encryptedData = sas.key(privateKey).encrypt(data);
    assert.equal(sas.key(publicKey, 'public').decrypt(encryptedData), data);
  });

  it("public key encrypt, private key decrypt", () => {
    let encryptedData = sas.key(publicKey, 'public').encrypt(data);
    assert.equal(sas.key(privateKey, 'private').decrypt(encryptedData), data);
  });
});

