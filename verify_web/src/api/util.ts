import type { User } from "./types";

export function compareVerify(a: User, b: User) {
  if (!a) {
    return 1;
  } else {
    return -1;
  }
}

export function compareYear(a: User, b: User) {
  if (a.year > b.year) {
    return 1;
  } else {
    return -1;
  }
}

export function compareDate(a: User, b: User) {
  if (a > b) {
    return 1;
  } else {
    return -1;
  }
}

export function shortPem(pem: string) {
  const begin = "-----BEGIN CERTIFICATE-----";
  const end = "-----END CERTIFICATE-----";
  const cleanPem = pem.replace(begin, "").replace(end, "");
  return [cleanPem.substring(0, 100), cleanPem.substring(pem.length - 200)]
}
