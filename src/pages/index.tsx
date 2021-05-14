import Head from 'next/head';
import { useCallback, useEffect, useState } from 'react';
import { FileWithPath, useDropzone } from 'react-dropzone';
import forge from 'node-forge';

export default function Home() {
  const [pfxPassword, setPfxPassword] = useState<string>();
  const [pfxFile, setPfxFile] = useState<FileWithPath>();
  const [privateKey, setPrivateKey] = useState<string>();
  const [cert, setCert] = useState<string>();
  const [caCert, setCaCert] = useState<string>();
  const [contentToSign, setContentToSign] = useState<string>();
  const [contentToSignSHA256Digest, setContentToSignSHA256Digest] =
    useState<forge.md.MessageDigest>();
  const [signature, setSignature] = useState<string>();
  const [isValidsignature, setIsValidSignature] = useState<boolean>();
  const [certificateValidation, setCertificateValidation] = useState<string>();

  const { acceptedFiles, getRootProps, getInputProps } = useDropzone({
    multiple: false,
    onDrop: async (acceptedFiles: FileWithPath[], _fileRejection, _event) =>
      setPfxFile(acceptedFiles[0]!),
  });

  const openPfx = useCallback(async () => {
    if (pfxFile && pfxPassword) {
      try {
        const p12b64 = Buffer.from(await pfxFile.arrayBuffer()).toString(
          'base64'
        );
        const p12Der = forge.util.decode64(p12b64);
        const p12Asn1 = forge.asn1.fromDer(p12Der);
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, pfxPassword);
        p12.safeContents.forEach(({ encrypted, safeBags }) => {
          if (!encrypted) {
            safeBags.forEach((bag) => {
              if (bag.key) setPrivateKey(forge.pki.privateKeyToPem(bag.key));
              if (bag.cert) {
                bag.cert.extensions.forEach((extension) => {
                  if (extension['keyCertSign'] !== undefined) {
                    if (extension['keyCertSign'])
                      setCaCert(forge.pki.certificateToPem(bag.cert!));
                    else setCert(forge.pki.certificateToPem(bag.cert!));
                  }
                });
              }
            });
          }
        });
      } catch (error) {
        alert(error);
      }
    } else alert('Inclua o arquivo PFX e a Senha');
  }, [pfxFile, pfxPassword]);

  const files = acceptedFiles.map((file: FileWithPath) => (
    <li key={file.path}>
      {file.path} - {file.size} bytes
    </li>
  ));

  useEffect(() => {
    if (contentToSign) {
      const md = forge.md.sha256.create();
      md.update(contentToSign, 'utf8');
      setContentToSignSHA256Digest(md);
    }
  }, [contentToSign]);

  const ContentToSignSHA256DigestHex = useCallback(
    () => (
      <p>
        <strong>SHA256: </strong>
        {contentToSignSHA256Digest?.digest().toHex()}
      </p>
    ),
    [contentToSignSHA256Digest]
  );

  const signSHA256DigestContent = useCallback(() => {
    if (privateKey !== undefined && contentToSignSHA256Digest !== undefined) {
      setSignature(
        forge.util.bytesToHex(
          forge.pki
            .privateKeyFromPem(privateKey)
            .sign(contentToSignSHA256Digest)
        )
      );
    }
  }, [privateKey, contentToSignSHA256Digest]);

  const SignedSHA256DigestHex = useCallback(
    () => (
      <div className='w-full break-all'>
        <p>
          <strong>Assinatura do SHA256 Hash: </strong>
          {signature}
        </p>
      </div>
    ),
    [signature]
  );

  const verifySignatureOfSHA256DigestContent = useCallback(() => {
    if (
      cert !== undefined &&
      signature !== undefined &&
      contentToSignSHA256Digest !== undefined
    ) {
      const certificate = forge.pki.certificateFromPem(cert);
      const publicKey = forge.pki.publicKeyFromPem(
        forge.pki.publicKeyToPem(certificate.publicKey)
      );
      setIsValidSignature(
        publicKey.verify(
          contentToSignSHA256Digest.digest().bytes(),
          forge.util.hexToBytes(signature)
        )
      );
    }
  }, [cert, signature, contentToSignSHA256Digest]);

  const VerifySignedSHA256DigestHex = useCallback(
    () => (
      <div className='w-full break-all'>
        <p>
          <strong>
            Verificação de Assinatura do SHA256 Hash com certificado do
            Assinador:{' '}
          </strong>
          {isValidsignature ? 'Válido' : 'Inválido'}
        </p>
      </div>
    ),
    [isValidsignature]
  );

  const verifyCertWithCACert = useCallback(() => {
    if (cert !== undefined && caCert !== undefined) {
      const certificate = forge.pki.certificateFromPem(cert);
      const caCertificate = forge.pki.certificateFromPem(caCert);
      try {
        setCertificateValidation(
          caCertificate.verify(certificate)
            ? 'Certificado Validado pelo Certificado da CA'
            : 'Certificado Invalidado pelo Certificado da CA'
        );
      } catch (error) {
        setCertificateValidation(
          'Certificado Inválido ou Não Emitido pelo certificado da CA em questão'
        );
      }
    }
  }, [cert, caCert]);

  return (
    <>
      <Head>
        <title>Create Next App</title>
        <meta name='description' content='Generated by create next app' />
        <link rel='icon' href='/favicon.ico' />
      </Head>
      <main className='w-full  p-10 flex flex-col space-y-4'>
        <input
          type='password'
          placeholder='Senha / PIN'
          onChange={(e) => setPfxPassword(e.currentTarget.value)}
        />

        <section>
          <div {...getRootProps({ className: 'border-2 border-dashed' })}>
            <input {...getInputProps()} />
            <p>Drag 'n' drop some files here, or click to select files</p>
          </div>
          <aside>
            <h4>Files</h4>
            <ul>{files}</ul>
          </aside>
        </section>
        <button
          type='button'
          className='bg-black text-white rounded-lg p-2 disabled:bg-gray-700 '
          disabled={
            (pfxPassword === undefined || pfxPassword?.length === 0) &&
            pfxFile === undefined
          }
          onClick={openPfx}
        >
          Abrir arquivo PFX
        </button>
        {privateKey && cert && caCert && (
          <div className='flex flex-col space-y-4'>
            <div className='flex flex-row space-x-4 w-44 text-xs font-mono '>
              <div>
                <strong>Chave Privada do Assinador</strong>
                <br />
                {privateKey}
              </div>
              <div>
                <strong>Certificado Digital do Assinador</strong>
                <br />
                {certificateValidation && (
                  <i>
                    {certificateValidation}
                    <br />
                  </i>
                )}
                {cert}
              </div>
              <div>
                <strong>Certificado Digital da Autoridade Certificadora</strong>
                <br />
                {caCert}
              </div>
            </div>
            <button
              type='button'
              className='bg-black text-white rounded-lg p-2 disabled:bg-gray-700 '
              disabled={cert === undefined && caCert === undefined}
              onClick={verifyCertWithCACert}
            >
              Verificar Certificado Digital do Assinador com Certificado Digital
              da CA
            </button>
            <input
              type='text'
              placeholder='Texto para Assinar'
              onChange={(e) => setContentToSign(e.currentTarget.value)}
            />
            <ContentToSignSHA256DigestHex />
            <button
              type='button'
              className='bg-black text-white rounded-lg p-2 disabled:bg-gray-700 '
              disabled={
                privateKey === undefined &&
                contentToSignSHA256Digest === undefined
              }
              onClick={signSHA256DigestContent}
            >
              Assinar Hash do Conteúdo com Chave privada do Assinador
            </button>
            <SignedSHA256DigestHex />
            {signature && cert && (
              <>
                <button
                  type='button'
                  className='bg-black text-white rounded-lg p-2 disabled:bg-gray-700 '
                  disabled={cert === undefined && signature === undefined}
                  onClick={verifySignatureOfSHA256DigestContent}
                >
                  Verificar Assinatura do SHA256 Hash com Certificado Digital do
                  Assinador
                </button>
                <VerifySignedSHA256DigestHex />
              </>
            )}
          </div>
        )}
      </main>
    </>
  );
}
