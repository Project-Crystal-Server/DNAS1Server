/*
===========================================================================
Copyright (C) 2019-2026 Project Crystal Dev Team

This file is part of Project Crystal Server.

Project Crystal Server is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Project Crystal Server is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Project Crystal Server. If not, see <https://www.gnu.org/licenses/>.
===========================================================================

Special thanks to Luke Usher (Insignia) for research help.
Special thanks to l_oliveira for PS2 technical advice.
Special thanks to Pancakes (Dricaster) for key/certificate.

===========================================================================
*/

namespace Crystal.DNAS1Server.Tls
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Tls;
    using Org.BouncyCastle.Tls.Crypto;
    using Org.BouncyCastle.Tls.Crypto.Impl.BC;
    using Org.BouncyCastle.X509;

    // The certificate chain and private key the server presents, read from PEM files.
    public class ServerCredentials
    {
        public readonly Certificate Certificate;   // leaf first, then its issuers
        public readonly AsymmetricKeyParameter PrivateKey;

        private ServerCredentials(Certificate certificate, AsymmetricKeyParameter privateKey)
        {
            Certificate = certificate;
            PrivateKey = privateKey;
        }

        // Returns null (after reporting why) if a file is missing or malformed, or no certificate in the chain
        // file belongs to the key. The chain file may list its certificates in any order; they are sent leaf first.
        public static ServerCredentials? Read(BcTlsCrypto crypto, string certFile, string keyFile)
        {
            try
            {
                List<X509Certificate> certificates = new();
                foreach (object pem in ReadPem(certFile))
                {
                    if (pem is X509Certificate cert)
                        certificates.Add(cert);
                }
                if (certificates.Count == 0)
                    throw new InvalidDataException($"no certificate in {certFile}");

                RsaKeyParameters? privateKey = null;
                foreach (object pem in ReadPem(keyFile))
                {
                    if (pem is AsymmetricCipherKeyPair pair)
                        privateKey = pair.Private as RsaKeyParameters;       // "RSA PRIVATE KEY" (PKCS#1)
                    else if (pem is AsymmetricKeyParameter key && key.IsPrivate)
                        privateKey = key as RsaKeyParameters;                // "PRIVATE KEY" (PKCS#8)
                }
                if (privateKey == null)
                    throw new InvalidDataException($"no RSA private key in {keyFile}");

                // The leaf is whichever certificate carries the public half of the key.
                BigInteger keyModulus = privateKey.Modulus;
                X509Certificate? leaf = certificates.Find(cert => keyModulus.Equals(Modulus(cert)));
                if (leaf == null)
                {
                    string listed = string.Join(", ", certificates.ConvertAll(cert => $"{CommonName(cert)} ({Prefix(Modulus(cert))})"));
                    throw new InvalidDataException($"{keyFile} (modulus {Prefix(keyModulus)}) matches no certificate in {certFile}: {listed}");
                }

                // Leaf first, then follow the issuer links; anything unrelated keeps its file order at the end.
                List<X509Certificate> ordered = new() { leaf };
                X509Certificate current = leaf;
                while (true)
                {
                    X509Certificate subject = current;
                    X509Certificate? issuer = certificates.Find(cert => !ordered.Contains(cert) && cert.SubjectDN.Equivalent(subject.IssuerDN));
                    if (issuer == null)
                        break;
                    ordered.Add(issuer);
                    current = issuer;
                }
                foreach (X509Certificate cert in certificates)
                {
                    if (!ordered.Contains(cert))
                        ordered.Add(cert);
                }

                TlsCertificate[] chain = new TlsCertificate[ordered.Count];
                for (int i = 0; i < ordered.Count; i++)
                    chain[i] = new BcTlsCertificate(crypto, ordered[i].GetEncoded());

                return new ServerCredentials(new Certificate(chain), privateKey);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Cannot load TLS credentials: {e.Message}");
                return null;
            }
        }

        private static BigInteger? Modulus(X509Certificate cert)
        {
            return (cert.GetPublicKey() as RsaKeyParameters)?.Modulus;
        }

        // First hex digits of a modulus: enough to tell keys apart in a log line.
        private static string Prefix(BigInteger? modulus)
        {
            if (modulus == null)
                return "not RSA";
            string hex = modulus.ToString(16).ToUpperInvariant();
            return (hex.Length > 8 ? hex.Substring(0, 8) : hex) + "...";
        }

        private static string CommonName(X509Certificate cert)
        {
            IList<string> names = cert.SubjectDN.GetValueList(X509Name.CN);
            return names.Count > 0 ? names[0] : cert.SubjectDN.ToString();
        }

        private static List<object> ReadPem(string path)
        {
            List<object> objects = new();
            using (StreamReader text = File.OpenText(path))
            using (PemReader pem = new(text))
            {
                object? obj;
                while ((obj = pem.ReadObject()) != null)
                    objects.Add(obj);
            }
            return objects;
        }
    }
}
