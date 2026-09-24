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
    using System.IO;
    using Org.BouncyCastle.Tls;

    // TlsServerProtocol without BouncyCastle's 1/n-1 record splitting. BouncyCastle sends the first byte of
    // every write as a record of its own (a 2011 BEAST countermeasure for CBC ciphers in TLS 1.0 and SSL 3.0).
    // Servers of the console's era never did that, and RC4 gains nothing from it, so application data is
    // written out as whole records here.
    public class LegacyTlsServerProtocol : TlsServerProtocol
    {
        public LegacyTlsServerProtocol(Stream stream) : base(stream)
        {
        }

        // Each connection is served by a single thread after Accept() has returned, so no write lock is needed.
        public override void WriteApplicationData(byte[] buffer, int offset, int count)
        {
            while (count > 0)
            {
                if (IsClosed)
                    throw new IOException("Cannot write application data on closed/failed TLS connection");

                int toWrite = Math.Min(count, ApplicationDataLimit);
                SafeWriteRecord(ContentType.application_data, buffer, offset, toWrite);
                offset += toWrite;
                count -= toWrite;
            }
        }

        public override void WriteApplicationData(ReadOnlySpan<byte> buffer)
        {
            WriteApplicationData(buffer.ToArray(), 0, buffer.Length);
        }
    }
}
