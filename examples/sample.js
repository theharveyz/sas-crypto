import SAS from 'sas';

const sas = new SAS();
const data = 'hello';
const privateKey = 'xxxxxxxx';
const publickey = 'xxxxxxxx';

let encryptedData = sas.key(privateKey, 'private').encrypt(data);
let decryptedData = sas.key(publickey, 'public').decrypt(encryptedData);
console.log(decryptedData);
// output: hello


encryptedData = sas.key(publickey, 'public').encrypt(data);
decryptedData = sas.key(privateKey, 'private').decrypt(encryptedData);
console.log(decryptedData);
// output: hello
