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

namespace Crystal.DNAS1Server.DNAS1.Send
{
    public class InitializeResponse
    {
        public readonly byte? Result;
        public readonly byte[] Security;

        public const int OPCODE = 0x5;

        public InitializeResponse(byte[] security, byte? result = null)
        {
            Result = result;
            Security = security;
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[Result != null ? 0x1A : 0x19];

            using (MemoryStream mstream = new(result))
            using (BinaryWriter writer = new(mstream))
            {
                if (Result != null)
                    writer.Write((byte)Result);
                writer.Write(Security);
            }

            return result;
        }
    }
}
