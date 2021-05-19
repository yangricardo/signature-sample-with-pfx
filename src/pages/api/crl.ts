import type { NextApiRequest, NextApiResponse } from 'next';
import { crlDecoder } from '@/helpers/crl-decoder';
import fs from 'fs';
import path from 'path';
export default (req: NextApiRequest, res: NextApiResponse) => {
  const serialNumber = req.query.serialNumber as string | undefined;
  if (serialNumber === undefined || serialNumber === '')
    res
      .status(400)
      .json({ message: 'serialNumber query parameter is required' });
  const crlBuffer = fs.readFileSync(
    path.join(__dirname, '..', '..', '..', '..', 'ca2.crl')
  );
  const revokedCertificateSerialNumbers = crlDecoder(crlBuffer);
  const revokedSerialNumberFound = revokedCertificateSerialNumbers.find(
    (revokedSerialNumber) => revokedSerialNumber === serialNumber?.toUpperCase()
  );
  res.status(200).json({
    serialNumber,
    isRevoked: revokedSerialNumberFound !== undefined,
    revokedCertificateSerialNumbers,
  });
};
