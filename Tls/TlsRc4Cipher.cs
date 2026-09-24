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
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Tls;
    using Org.BouncyCastle.Tls.Crypto;
    using Org.BouncyCastle.Tls.Crypto.Impl;

    // RC4-128 record protection for SSL 3.0 / TLS 1.0-1.2 (TLS_RSA_WITH_RC4_128_MD5 and _SHA).
    //
    // A stream-cipher record is RC4(content || MAC) with a keystream that runs on across records.
    // BouncyCastle's own TlsNullCipher already produces exactly "content || MAC" on encode and verifies
    // it on decode, so this class wraps one and applies the RC4 keystream on top, one engine per direction.
    public class TlsRc4Cipher : TlsCipher, TlsCipherExt
    {
        public const int KEY_SIZE = 16;

        private readonly TlsNullCipher MacCipher;
        private readonly RC4Engine Encoder = new();
        private readonly RC4Engine Decoder = new();

        public TlsRc4Cipher(TlsCryptoParameters cryptoParams, TlsHmac clientMac, TlsHmac serverMac)
        {
            // TlsNullCipher derives client/server_write_MAC_secret from the first 2 * mac_length bytes of the
            // key block itself. The write keys follow them (RFC 2246 6.3, SSL 3.0 6.2.2), and the key-block
            // derivation is prefix-consistent, so a longer key block computed here yields the same MAC
            // secrets followed by the two RC4 keys.
            MacCipher = new TlsNullCipher(cryptoParams, clientMac, serverMac);

            int macLength = clientMac.MacLength;
            byte[] keyBlock = TlsImplUtilities.CalculateKeyBlock(cryptoParams, 2 * macLength + 2 * KEY_SIZE);
            KeyParameter clientKey = new(keyBlock, 2 * macLength, KEY_SIZE);
            KeyParameter serverKey = new(keyBlock, 2 * macLength + KEY_SIZE, KEY_SIZE);
            Array.Clear(keyBlock);

            if (cryptoParams.IsServer)
            {
                Encoder.Init(true, serverKey);
                Decoder.Init(false, clientKey);
            }
            else
            {
                Encoder.Init(true, clientKey);
                Decoder.Init(false, serverKey);
            }
        }

        public TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int offset, int len)
        {
            TlsEncodeResult result = MacCipher.EncodePlaintext(seqNo, contentType, recordVersion, headerAllocation, plaintext, offset, len);

            // The first headerAllocation bytes are reserved for the record header; encrypt the rest in place.
            int payloadOffset = result.off + headerAllocation;
            int payloadLength = result.len - headerAllocation;
            Encoder.ProcessBytes(result.buf, payloadOffset, payloadLength, result.buf, payloadOffset);
            return result;
        }

        public TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext)
        {
            return EncodePlaintext(seqNo, contentType, recordVersion, headerAllocation, plaintext.ToArray(), 0, plaintext.Length);
        }

        public TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int offset, int len)
        {
            Decoder.ProcessBytes(ciphertext, offset, len, ciphertext, offset);
            return MacCipher.DecodeCiphertext(seqNo, recordType, recordVersion, ciphertext, offset, len);
        }

        public int GetCiphertextDecodeLimit(int plaintextLimit)
        {
            return MacCipher.GetCiphertextDecodeLimit(plaintextLimit);
        }

        public int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
        {
            return MacCipher.GetCiphertextEncodeLimit(plaintextLength, plaintextLimit);
        }

        public int GetPlaintextLimit(int ciphertextLimit)
        {
            return MacCipher.GetPlaintextLimit(ciphertextLimit);
        }

        public int GetPlaintextDecodeLimit(int ciphertextLimit)
        {
            return MacCipher.GetPlaintextDecodeLimit(ciphertextLimit);
        }

        public int GetPlaintextEncodeLimit(int ciphertextLimit)
        {
            return MacCipher.GetPlaintextEncodeLimit(ciphertextLimit);
        }

        // Rekeying only exists in TLS 1.3, which never negotiates RC4.
        public void RekeyDecoder()
        {
            MacCipher.RekeyDecoder();
        }

        public void RekeyEncoder()
        {
            MacCipher.RekeyEncoder();
        }

        public bool UsesOpaqueRecordType
        {
            get { return MacCipher.UsesOpaqueRecordType; }
        }
    }
}
