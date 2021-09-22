import { PEMObject } from "pem-ts";

export function valid(pemString: string) {
  try {
    const pem: PEMObject = new PEMObject();
    pem.decode(pemString);
    return true;
  } catch (e) {
    return false;
  }
}

export function verify(pemString: string) {
  const pem: PEMObject = new PEMObject();
  pem.decode(pemString);

  const result: string = wasmVerifyMraCert(buf2hex(pem.data));
  return result;
}

function buf2hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
