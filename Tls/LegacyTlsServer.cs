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
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Tls;
    using Org.BouncyCastle.Tls.Crypto;
    using Org.BouncyCastle.Tls.Crypto.Impl.BC;

    // SSL/TLS policy for one connection: SSL 3.0 up to TLS 1.2 with RSA key exchange and the DNAS certificate.
    // The PS2 client negotiates SSL 3.0 with RC4; the 3DES/AES entries let current tools connect for testing.
    // A new instance is needed for every connection. Every handshake step is logged so a failing console
    // attempt shows exactly where it stopped.
    public class LegacyTlsServer : DefaultTlsServer
    {
        private static readonly int[] CipherSuites =
        {
            CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
            CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
            CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
        };

        private readonly ServerCredentials Credentials;

        public LegacyTlsServer(LegacyTlsCrypto crypto, ServerCredentials credentials) : base(crypto)
        {
            Credentials = credentials;
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.TLSv12.DownTo(ProtocolVersion.SSLv3);
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, CipherSuites);
        }

        // Choose in our order (RC4-128 first) rather than the client's, in case it lists export suites first.
        protected override bool PreferLocalCipherSuites()
        {
            return true;
        }

        // Servers of the era put the time in the first four bytes of the random (OpenSSL always did).
        public override bool ShouldUseGmtUnixTime()
        {
            return true;
        }
        // Servers of the era always handed out a session ID; an old client may expect one.
        public override byte[] GetNewSessionID()
        {
            byte[] id = new byte[32];
            Crypto.SecureRandom.NextBytes(id);
            return id;
        }

        // RFC 5746 secure renegotiation postdates the console by a decade, so its hello carries neither the
        // renegotiation_info extension nor the signalling suite. BouncyCastle rejects that by default; we never
        // renegotiate, so accept it.
        public override void NotifySecureRenegotiation(bool secureRenegotiation)
        {
        }

        // Static RSA key exchange: the client encrypts the pre-master secret to our certificate.
        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
        {
            //Console.WriteLine($"TLS sending certificate chain ({Credentials.Certificate.Length} certificates)");
            return new LoggingDecryptor((BcTlsCrypto)Crypto, Credentials.Certificate, Credentials.PrivateKey);
        }

        // --- handshake diagnostics, in the order they happen ---

        public override void NotifyHandshakeBeginning()
        {
            base.NotifyHandshakeBeginning();
            //Console.WriteLine("TLS handshake started");
        }

        public override void NotifyClientVersion(ProtocolVersion clientVersion)
        {
            base.NotifyClientVersion(clientVersion);
            //Console.WriteLine($"TLS client hello: {clientVersion}");
        }

        public override void NotifyOfferedCipherSuites(int[] offeredCipherSuites)
        {
            base.NotifyOfferedCipherSuites(offeredCipherSuites);
            //Console.WriteLine($"TLS client offered: {string.Join(", ", offeredCipherSuites.Select(suite => $"0x{suite:X4}"))}");
        }

        public override int GetSelectedCipherSuite()
        {
            int selected = base.GetSelectedCipherSuite();
            //Console.WriteLine($"TLS selected cipher suite 0x{selected:X4}");
            return selected;
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            SecurityParameters negotiated = m_context.SecurityParameters;
            //Console.WriteLine($"TLS established: {negotiated.NegotiatedVersion}, cipher suite 0x{negotiated.CipherSuite:X4}");
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message, Exception cause)
        {
            base.NotifyAlertRaised(alertLevel, alertDescription, message, cause);
            string detail = message ?? "";
            if (cause != null)
                detail += $" ({cause.Message})";
            //Console.WriteLine($"TLS alert sent: {AlertLevel.GetText(alertLevel)} {AlertDescription.GetText(alertDescription)} {detail}".TrimEnd());
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            base.NotifyAlertReceived(alertLevel, alertDescription);
            //Console.WriteLine($"TLS alert received: {AlertLevel.GetText(alertLevel)} {AlertDescription.GetText(alertDescription)}");
        }

        public override void NotifyConnectionClosed()
        {
            base.NotifyConnectionClosed();
            //Console.WriteLine("TLS connection closed");
        }

        // Reports the moment the client's key exchange arrives: reaching it means the client accepted the certificate.
        private class LoggingDecryptor : BcDefaultTlsCredentialedDecryptor
        {
            public LoggingDecryptor(BcTlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey)
                : base(crypto, certificate, privateKey)
            {
            }

            public override TlsSecret Decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext)
            {
                //Console.WriteLine($"TLS client key exchange received ({ciphertext.Length} bytes)");
                return base.Decrypt(cryptoParams, ciphertext);
            }
        }
    }
}
