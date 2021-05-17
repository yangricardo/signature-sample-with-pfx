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
  const [contentToSign, setContentToSign] =
    useState<string>('{"Hello":"World"}');
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
        <strong>Hash SHA256 a ser assinado e verificado: </strong>
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

  useEffect(
    () => verifySignatureOfSHA256DigestContent(),
    [cert, signature, contentToSignSHA256Digest]
  );

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
        <title>PFX Signature Sample</title>
        <meta
          name='description'
          content='Sample of web application used to sign a text using client PFX file containing it`s private key and certs validation'
        />
        <link rel='icon' href='/favicon.ico' />
      </Head>
      <main className='w-full  p-10 flex flex-col space-y-4'>
        <label>Senha para assinar com o arquivo PFX</label>
        <input
          type='password'
          placeholder='Senha / PIN'
          onChange={(e) => setPfxPassword(e.currentTarget.value)}
        />
        <div
          {...getRootProps({
            className: 'border-2 border-dashed p-5 cursor-pointer',
          })}
        >
          <input {...getInputProps()} />
          <p>Clique aqui para carregar o arquivo PFX</p>
        </div>

        {acceptedFiles[0] && (
          <>
            <p>Arquivo carregado:</p>
            <ul>
              <li>Nome: {acceptedFiles[0].name} </li>
              <li>Tamanho: {acceptedFiles[0].size} </li>
              <li>Tipo: {acceptedFiles[0].type} </li>
            </ul>
          </>
        )}

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
            <label>Texto para assinar</label>
            <input
              type='text'
              placeholder='Texto para Assinar'
              defaultValue={contentToSign}
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
