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

namespace Crystal.DNAS1Server
{
    public class Utils
    {
        public static ulong SwapEndian(ulong input)
        {
            return 0x00000000000000FF & (input >> 56) |
                   0x000000000000FF00 & (input >> 40) |
                   0x0000000000FF0000 & (input >> 24) |
                   0x00000000FF000000 & (input >> 8) |
                   0x000000FF00000000 & (input << 8) |
                   0x0000FF0000000000 & (input << 24) |
                   0x00FF000000000000 & (input << 40) |
                   0xFF00000000000000 & (input << 56);
        }

        public static uint SwapEndian(uint input)
        {
            return ((input >> 24) & 0xff) |
                   ((input << 8) & 0xff0000) |
                   ((input >> 8) & 0xff00) |
                   ((input << 24) & 0xff000000);
        }

        public static int SwapEndian(int input)
        {
            var inputAsUint = (uint)input;

            input = (int)
                (((inputAsUint >> 24) & 0xff) |
                 ((inputAsUint << 8) & 0xff0000) |
                 ((inputAsUint >> 8) & 0xff00) |
                 ((inputAsUint << 24) & 0xff000000));

            return input;
        }

        public static ushort SwapEndian(ushort input)
        {
            return (ushort)(((input << 8) & 0xff00) |
                            ((input >> 8) & 0x00ff));
        }

    }
}
