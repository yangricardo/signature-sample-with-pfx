/* eslint-disable @typescript-eslint/no-var-requires */

export function crlDecoder(crlBuffer: Buffer): string[] {
  const asn1 = require('asn1js');
  const pkijs = require('pkijs');
  const pvutils = require('pvutils');
  const uint8CrlBuffer = new Uint8Array(crlBuffer).buffer;
  const asn1crl = asn1.fromBER(uint8CrlBuffer);
  const crl = new pkijs.CertificateRevocationList({
    schema: asn1crl.result,
  });
  // console.log(crl);
  let revokedCertificates = [];
  if (crl.revokedCertificates) {
    revokedCertificates = crl.revokedCertificates.map(
      ({ userCertificate }: { userCertificate: any }) =>
        pvutils.bufferToHexCodes(userCertificate.valueBlock.valueHex)
    );
  }
  return revokedCertificates as string[];
}

if (typeof require !== 'undefined' && require.main === module) {
  const fs = require('fs');
  const crlBuffer = fs.readFileSync('ca2.crl');
  console.log(crlDecoder(crlBuffer));
}
