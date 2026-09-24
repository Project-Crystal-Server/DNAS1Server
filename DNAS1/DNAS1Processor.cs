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

using Crystal.DNAS1Server.DNAS1.Receive;
using Crystal.DNAS1Server.DNAS1.Send;

namespace Crystal.DNAS1Server.DNAS1
{
    public class DNAS1Processor()
    {
        public bool Process(byte[] requestPacket, out byte[]? responsePacket)
        {
            // Verify packet sizes and get the header
            responsePacket = null;
            if (requestPacket.Length < PacketHeader.SIZE)
                return false;

            PacketHeader? header = PacketHeader.Parse(requestPacket);
            if (header == null || PacketHeader.SIZE + header.DataSize < requestPacket.Length)
                return false;

            // Process packet
            byte[] data = requestPacket[PacketHeader.SIZE..];
            switch (header.Opcode & 0xFF)
            {
                case 0:
                    {
                        InitializeRequest? request = InitializeRequest.Read(data);
                        if (request != null)
                        {
                            Console.WriteLine($"DNAS1 initialize request");
                            bool isHddActivated = (header.Flags & 0x8000) != 0;
                            byte[] responseData;
                            if (isHddActivated)
                                responseData = new InitializeResponse(new byte[25], 0).GetBytes();
                            else
                                responseData = new InitializeResponse(new byte[25]).GetBytes();
                            responsePacket = new PacketHeader(header.Flags, (ushort)((header.Opcode & 0xFF00) | InitializeResponse.OPCODE), header.Security, (uint)responseData.Length).GetPacket(responseData);
                            return true;
                        }
                        break;
                    }
                case 1:
                    {
                        SetHddActivationSecretRequest? request = SetHddActivationSecretRequest.Read(data);
                        byte[] responseData = new SetHddActivationSecretResponse(new byte[6]).GetBytes();
                        responsePacket = new PacketHeader(header.Flags, (ushort)((header.Opcode & 0xFF00) | SetHddActivationSecretResponse.OPCODE), header.Security, (uint)responseData.Length).GetPacket(responseData);
                        Console.WriteLine($"DNAS1 HDD activate request");
                        break;
                    }
                case 2:
                    {
                        InstallRequest? request = InstallRequest.Read(data);
                        byte[] responseData = new InstallResponse(0).GetBytes();
                        responsePacket = new PacketHeader(header.Flags, (ushort)((header.Opcode & 0xFF00) | InstallResponse.OPCODE), header.Security, (uint)responseData.Length).GetPacket(responseData);
                        Console.WriteLine($"DNAS1 install request");
                        break;
                    }
                case 3:
                    // Haven't seen this in the wild
                    break;
                case 8:
                    // Haven't seen this in the wild
                    break;
                default:
                    return false;
            }

            return true;
        }
    }
}
