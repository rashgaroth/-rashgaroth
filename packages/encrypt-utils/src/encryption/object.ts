import * as crypto from 'crypto';
import { IObjectEncryption } from '../interfaces';

export default class ObjectEncryption {
  key: string

  matcher: string

  constructor({
    key,
    matcher = "!!"
  }: IObjectEncryption) {
    this.key = key;
    this.matcher = matcher;
    if (!key) {
      throw new Error("Key is not assigned to constructor")
    }
  }
  replaceAll = (str: string, searchValue: string, replaceValue: string) => str.split(searchValue).join(replaceValue);
  swap = (str: string, input: string, output: string) => {
    for (let i = 0; i < input.length; i++) str = this.replaceAll(str, input[i], output[i]);
  
    return str;
  };
  createBase64Hmac = (message: string) =>
  this.swap(
    crypto.createHmac("sha1", this.key).update(`${message}`).digest("hex"),
    "+=/", // Used to avoid characters that aren't safe in URLs
    "-_,"
  );
  sign = (message: string) => `${new Date().getTime()}-!!-${this.createBase64Hmac(message)}`;
  verify = (message: string, hash: string) => {
    const matches = hash.match(/(.+?)-!!-(.+)/);
    if (!matches) return false;
    const hmac = matches[2];
    const expectedHmac = this.createBase64Hmac(message);
    // Byte lengths must equal, otherwise crypto.timingSafeEqual will throw an exception
    if (hmac.length !== expectedHmac.length) return false;
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expectedHmac));
  };
  createDigest(encodedData: crypto.BinaryLike, format: crypto.BinaryToTextEncoding) {
    return crypto.createHmac("sha256", this.key).update(encodedData).digest(format);
  };
  encode(sourceData: Partial<{
    [x: string]: string
  }>) {
    const json = JSON.stringify(sourceData);
    const encodedData = Buffer.from(json).toString("base64");
    return `${encodedData}!${this.createDigest(encodedData, "base64")}`;
  }
  decode(value: string) {
    const [encodedData, sourceDigest] = value.split("!");
    if (!encodedData || !sourceDigest) throw new Error("invalid value(s)");
    const json = Buffer.from(encodedData, "base64").toString("utf8");
    const decodedData = JSON.parse(json);
    const checkDigest = this.createDigest(encodedData, "hex");
    const digestsEqual = crypto.timingSafeEqual(
      Buffer.from(sourceDigest, "base64"),
      Buffer.from(checkDigest, "hex")
    );
    if (!digestsEqual) throw new Error("invalid value(s)");
    return decodedData;
  }
}