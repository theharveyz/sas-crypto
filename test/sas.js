import fs from 'fs';
import ursa from 'ursa';
import test from 'ava';
import SAS from '../src';

const sas = new SAS();
const privateKey = fs.readFileSync('./test/_fixture/private.pem');
const publicKey = fs.readFileSync('./test/_fixture/public.pub');
const data = 'hello sas!'


test('random hash aes key length should be 64', t => {
  const aesKey = sas.createRandomHash();
  t.is(aesKey.length, 64);
});

test('specify key', t => {
  const str = privateKey.toString('utf8');
  const rsakey = sas.key(str).rsakey;
  t.true(typeof(str) === 'string');
  t.true(ursa.isPrivateKey(rsakey));
});

test('private key encrypt, public key decrypt', t => {
  const encryptedData = sas.key(privateKey).encrypt(data);
  t.is(sas.key(publicKey, 'public').decrypt(encryptedData), data);
});

test('public key encrypt, private key decrypt', t => {
  sas.key(publicKey, 'public');
  const encryptedData = sas.encrypt(data);

  sas.key(privateKey, 'private');
  t.is(sas.decrypt(encryptedData), data);
});

