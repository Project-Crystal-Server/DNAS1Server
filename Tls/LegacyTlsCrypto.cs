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
    using Org.BouncyCastle.Tls;
    using Org.BouncyCastle.Tls.Crypto;
    using Org.BouncyCastle.Tls.Crypto.Impl.BC;

    // BouncyCastle's crypto provider with RC4 put back. The PS2 DNAS client is an SSL 3.0 stack that
    // uses RC4-MD5 / RC4-SHA, which BouncyCastle no longer offers by itself.
    public class LegacyTlsCrypto : BcTlsCrypto
    {
        public override bool HasEncryptionAlgorithm(int encryptionAlgorithm)
        {
            if (encryptionAlgorithm == EncryptionAlgorithm.RC4_128)
                return true;
            return base.HasEncryptionAlgorithm(encryptionAlgorithm);
        }

        public override TlsCipher CreateCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)
        {
            // CreateMac returns the SSL 3.0 MAC or the TLS HMAC, whichever the negotiated version needs.
            if (encryptionAlgorithm == EncryptionAlgorithm.RC4_128)
                return new TlsRc4Cipher(cryptoParams, CreateMac(cryptoParams, macAlgorithm), CreateMac(cryptoParams, macAlgorithm));
            return base.CreateCipher(cryptoParams, encryptionAlgorithm, macAlgorithm);
        }
    }
}
