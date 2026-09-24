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

using System.Text;

namespace Crystal.DNAS1Server.DNAS1.Receive
{
    public class InitializeRequest
    {
        public readonly uint Unknown;
        public readonly ulong Passphrase;
        public readonly byte[] DiscId;
        public readonly string GameId;
        public readonly byte[] ILinkId;
        public readonly byte[] ConsoleId;
        public readonly byte[] HddInfo;
        public readonly byte[] HddNonce;
        public readonly byte[] HddKey;
        public readonly bool IsActivated = false;

        public const int SIZE = 0x28;

        public static InitializeRequest? Read(byte[] data)
        {
            try
            {
                return new InitializeRequest(data);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private InitializeRequest(byte[] data)
        {

            using MemoryStream mstream = new(data);
            using BinaryReader reader = new(mstream);

            Unknown = reader.ReadUInt32();
            Passphrase = reader.ReadUInt64();
            DiscId = reader.ReadBytes(0x5);
            GameId = Encoding.ASCII.GetString(reader.ReadBytes(0x9));
            ILinkId = FixILinkId(reader.ReadBytes(0x10));
            HddInfo = reader.ReadBytes(0x20);

            if (data.Length == 0x5E)
            { 
                HddNonce = reader.ReadBytes(0x4);
                HddKey = reader.ReadBytes(0x10);
                IsActivated = true;
            }
        }

        private byte[] FixILinkId(byte[] data)
        {
            uint low = BitConverter.ToUInt32(data, 0);
            uint high = BitConverter.ToUInt32(data, 4);
            low = Utils.SwapEndian(low);
            high = Utils.SwapEndian(high);
            ulong combined = low | ((ulong)high << 32);
            return BitConverter.GetBytes(combined);
        }

        // 0x00 -> 0x40 (0x08 bytes)
        // 0x08 -> 0x50 (0x10 bytes)
        // 
    }

}
