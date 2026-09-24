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
    public class ErrorResponse
    {
        public readonly byte ErrorCode;

        public const int OPCODE = 0xC;

        public ErrorResponse(byte errorCode)
        {
            ErrorCode = errorCode;
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[0x1];

            using (MemoryStream mstream = new(result))
            using (BinaryWriter writer = new(mstream))
            {
                writer.Write(ErrorCode);
            }

            return result;
        }
    }
}
