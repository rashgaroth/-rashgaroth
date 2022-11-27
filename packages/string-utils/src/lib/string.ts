export const makeRandomDeg = (): number => {
  return Math.random() * 10
}
export const toSmallUnit = (price: number, decimal: number): number => {
  return price / Math.pow(10, decimal)
}
export const hideString = (price: number, dcm: number) => {
  return toSmallUnit(price, dcm).toString().replace(/[0-9]/g, '*')
}
export const truncateString = (str: string, n: number, useWordBoundary = '...'): string =>
  str.length > n ? str.substring(0, n - 3) + useWordBoundary : str
export const truncateWalletAddress = (input = '', n = 10): string => {
  if (input.length > n) {
    const sbstr = input.substring(0, n - 1)
    const revSbstr = input
      .split('')
      .reverse()
      .join('')
      .substring(0, n - 2)
    const finalString = `${sbstr} ... ${revSbstr}`
    return finalString
  } else {
    return input
  }
}
export const toNormalUnit = (price: number | string, decimal: number): bigint => BigInt(typeof price === 'string' ? parseInt(price) : price as number * Math.pow(10, decimal))
export const generateRandomString = (length: number): string => {
  let result = ''
  const characters = '1234567890'
  const charactersLength = characters.length
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength))
  }
  return result
}
export const generatePurchase = (): bigint => BigInt(Math.random() * 61 + Date.now())
export const generateId = (n: number): string => {
  const add = 1
  let max = 12 - add
  // 12 is the min safe number Math.random() can generate without it starting to pad the end with zeros.
  if (n > max) {
    return generateId(max) + generateId(n - max)
  }

  max = Math.pow(10, n + add)
  const min = max / 10 // Math.pow(10, n) basically
  const number = Math.floor(Math.random() * (max - min + 1)) + min

  return ('' + number).substring(add)
}
export const randomString = (length: number): string => {
  let result = ''
  const characters = 'abcdef1234567890'
  const charactersLength = characters.length
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength))
  }
  return result
}
export const toCodeUnit = (str: string): number[] => {
  const arr: number[] = []
  const buf = new Buffer(str, 'utf16le')
  for (let i = 0; i < buf.length; i++) {
    arr.push(buf[i])
  }
  return arr
}
export const fancyTimeFormat = (duration: number): string => {
  // Hours, minutes and seconds
  const hrs = ~~(duration / 3600)
  const mins = ~~((duration % 3600) / 60)
  const secs = ~~duration % 60
  // Output like "1:01" or "4:03:59" or "123:03:59"
  let ret = ''
  if (hrs > 0) {
    ret += '' + hrs + ':' + (mins < 10 ? '0' : '')
  }
  ret += '' + mins + ':' + (secs < 10 ? '0' : '')
  ret += '' + secs
  return ret
}
export const capitalize = (s: string) => (s && s[0].toUpperCase() + s.slice(1)) || ''
export const pathToCapitalizeString = (path: string, isLastIndex = false, index = 0) => {
  if (isLastIndex && index === undefined) {
    throw new Error('index cannot be undefined')
  }
  const currentPathArray = path.split('/')
  const selectedString = currentPathArray[!isLastIndex ? currentPathArray.length - 1 : index]
  return capitalize(selectedString)
}
const monthArray = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December'
]
export const convertDateToHumanDate = (date: Date): string => {
  const month = monthArray[date.getMonth()]
  const day = date.getDate()
  const year = date.getFullYear()

  return `${day} ${month} ${year}`
}
export function toDateTime(secs: number) {
  const t = new Date(1970, 0, 1) // Epoch
  t.setSeconds(secs)
  return t
}
export const generatePassword = (charset: string) => {
  const length = 8
  let retVal = ''
  for (let i = 0, n = charset.length; i < length; ++i) {
    retVal += charset.charAt(Math.floor(Math.random() * n))
  }
  return retVal
}
export const formatBytes = (bytes: number, decimals = 2) => {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}
export const isInteger = (value: number | string) => { return (typeof(value) === "number" && value == value && (value % 1) === 0); }
export const isHexString = (value: string, length: number) => {
  if (typeof(value) !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) { return false; }
  if (length && value.length !== 2 + 2 * length) { return false; }
  return true;
}

export const isBytes = (value: Uint8Array) => {
  if (value == null) { return false; }
  if (value.constructor === Uint8Array) { return true; }
  if (typeof(value) === 'string') { return false; }
  if (!isInteger(value.length) || value.length < 0) { return false; }
  for (let i = 0; i < value.length; i++) {
    const v = value[i];
    if (!isInteger(v) || v < 0 || v >= 256) { return false; }
  }
  return true;
}

export const checkSafeUint53 = (value: number, message: string) => {
  if (typeof(value) !== 'number') { return; }
  if (message == null) { message = 'value not safe'; }
  if (value < 0 || value >= 0x1fffffffffffff) {
    console.error(
      new Error(
        message + '. ' +
        JSON.stringify({
          operation: 'checkSafeInteger',
          fault: 'out-of-safe-range',
          value: value
        })
      )
    );
  }
  if (value % 1) {
    console.error(
      new Error(
        message + '. ' +
        JSON.stringify({
          operation: 'checkSafeInteger',
          fault: 'non-integer',
          value: value
        })
      )
    );
  }
}
export function capitalizeFirstLetter(string: string): string {
  return string.charAt(0).toUpperCase() + string.slice(1);
}
export const paginate = (array: unknown[], page_size: number, page_number: number) => {
  // human-readable page numbers usually start with 1, so we reduce 1 in the first argument
  return array.slice((page_number - 1) * page_size, page_number * page_size);
};
export const toFormattedBalance = (str: string) =>
  str.length > 4 ? `${str[0]}${str[1]}${str[2]}${str[3]}${str[4]}` : str;

export const toTimeFormat = (seconds: number) => {
  const d = Math.floor(seconds / (3600 * 24));
  const dDisplay = d > 0 ? d + (d == 1 ? " day " : " days ") : "";
  return dDisplay;
};