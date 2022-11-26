import ObjectEncryption from "../../src/encryption/object";

const objectEncryption = new ObjectEncryption({
  key: 'mykey',
  matcher: '!!'
})

const myObject = {
 name: 'rashgaroth',
 address: 'bali'
};

describe('Encryption utils test', () => { 
  test('Should return encrypted object', () => { 
    const encryptedObject = objectEncryption.encode(myObject);
    expect(typeof encryptedObject).toBe('string');
  })
  test('Should return a same object', () => {
    const encryptedObject = objectEncryption.encode(myObject);
    const decryptedObject = objectEncryption.decode(encryptedObject);
  
    expect(typeof encryptedObject).toBe('string');
    expect(decryptedObject).toMatchObject(myObject);
  })
  test('Should return correct hash string', () => {
    const hash = objectEncryption.sign('Hello!');
    const verify = objectEncryption.verify('Hello!', hash)
  
    expect(typeof hash).toBe('string')
    expect(verify).toBe(true)
  })
})