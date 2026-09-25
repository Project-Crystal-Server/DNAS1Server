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
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using DNAS1Server.DNAS1;
    using DNAS1Server.Tls;
    using Org.BouncyCastle.Tls;

    class DnasTcpServer
    {
        private const string DefaultRegion = "us";
        private const int Timeout = 10000;
        private const int MaxHeaderBytes = 8 * 1024;
        private const int MaxBodyBytes = 64 * 1024;

        private static DNAS1Processor Dnas1 = new();
        private static readonly LegacyTlsCrypto Crypto = new();
        private static ServerCredentials? Credentials;
        private static string Region = DefaultRegion;

        public static async Task<int> Main()
        {
            // Get region we are serving
            Region = (Environment.GetEnvironmentVariable("DNAS_REGION") ?? DefaultRegion).ToLowerInvariant();
            if (!Region.Equals("us") && !Region.Equals("jp"))
            {
                Console.Error.WriteLine("Invalid region selected");
                return 1;
            }

            // Get the IP we listen on (all interfaces unless set)
            IPAddress bindIp = IPAddress.Any;
            string? bindIpSetting = Environment.GetEnvironmentVariable("DNAS_BIND_IP");
            if (!string.IsNullOrEmpty(bindIpSetting) && !IPAddress.TryParse(bindIpSetting, out bindIp!))
            {
                Console.Error.WriteLine("Invalid bind IP selected");
                return 1;
            }

            // The certificate chain and key live in keys/ next to the executable.
            string certFile = Path.Combine(AppContext.BaseDirectory, "keys", $"dnas1.{Region}.chain.crt");
            string keyFile = Path.Combine(AppContext.BaseDirectory, "keys", $"dnas1.{Region}.key");
            Credentials = ServerCredentials.Read(Crypto, certFile, keyFile);
            if (Credentials == null)
            {
                Console.Error.WriteLine("Could not load credentials:");
                Console.Error.WriteLine($"  certificate: {certFile}");
                Console.Error.WriteLine($"  private key: {keyFile}");
                return 1;
            }

            // Stop on SIGTERM (systemd) or Ctrl+C
            using CancellationTokenSource shutdown = new();
            using PosixSignalRegistration sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx =>
            {
                ctx.Cancel = true;
                shutdown.Cancel();
            });
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                shutdown.Cancel();
            };

            TcpListener server = new TcpListener(bindIp, 443);
            server.Start();

            Console.WriteLine($"DNAS1 started (Region:{Region.ToUpper()}, IP:{bindIp})...");

            try
            {
                while (true)
                {
                    TcpClient client = await server.AcceptTcpClientAsync(shutdown.Token);
                    // The TLS stack does blocking I/O, so each connection is handled on a pool thread.
                    _ = Task.Run(() => HandleClient(client));
                }
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Shutting down.");
            }
            finally
            {
                server.Stop();
            }
            return 0;
        }

        private static void HandleClient(TcpClient client)
        {
            try
            {
                client.ReceiveTimeout = Timeout;
                client.SendTimeout = Timeout;
                client.NoDelay = true;   // send each record as soon as it is written, like the Apache servers of the era

                using (client)
                using (NetworkStream network = client.GetStream())
                {
                    TlsServerProtocol tls = new LegacyTlsServerProtocol(network);
                    try
                    {
                        // Handshake SSL
                        tls.Accept(new LegacyTlsServer(Crypto, Credentials!));
                        Stream stream = tls.Stream;

                        // Process HTTP
                        string? headers = ReadHeaders(stream);
                        if (headers == null)
                        {
                            SendBADResponse(stream);
                            return;
                        }

                        int contentLength = ParseContentLength(headers);
                        if (contentLength < 0 || contentLength > MaxBodyBytes)
                        {
                            SendBADResponse(stream);
                            return;
                        }

                        byte[] requestBody = new byte[contentLength];

                        if (contentLength > 0)
                        {
                            int bytesRead = 0;
                            while (bytesRead < contentLength)
                            {
                                int read = stream.Read(requestBody, bytesRead, contentLength - bytesRead);
                                if (read == 0) break;
                                bytesRead += read;
                            }
                        }

                        // Process DNAS
                        if (Dnas1.Process(requestBody, out byte[]? response))
                        {
                            SendOKResponse(response!, stream);
                            //Console.WriteLine("Sent HTTP/1.0 200 OK and closing.");
                        }
                        else
                        {
                            SendBADResponse(stream);
                            //Console.WriteLine("Sent HTTP/1.0 400 Bad Request and closing.");
                        }
                    }
                    finally
                    {
                        try { tls.Close(); } catch (Exception) { }
                    }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Connection error: {e}");
            }
        }

        private static void SendOKResponse(byte[] data, Stream stream)
        {
            StringBuilder responseHeader = new StringBuilder();
            responseHeader.Append("HTTP/1.0 200 OK\r\n");
            responseHeader.Append("Content-Type: image/gif\r\n");
            responseHeader.Append($"Content-Length: {data.Length}\r\n");
            responseHeader.Append("Connection: close\r\n");
            responseHeader.Append("\r\n");

            // One write, so the response goes out in as few TLS records as possible.
            byte[] headerBytes = Encoding.ASCII.GetBytes(responseHeader.ToString());
            byte[] responseBytes = new byte[headerBytes.Length + data.Length];
            headerBytes.CopyTo(responseBytes, 0);
            data.CopyTo(responseBytes, headerBytes.Length);
            stream.Write(responseBytes, 0, responseBytes.Length);
            stream.Flush();
        }

        private static void SendBADResponse(Stream stream)
        {
            StringBuilder responseHeader = new StringBuilder();
            responseHeader.Append("HTTP/1.0 400 Bad Request\r\n");
            responseHeader.Append("Content-Type: image/gif\r\n");
            responseHeader.Append("Connection: close\r\n");
            responseHeader.Append("\r\n");

            byte[] headerBytes = Encoding.ASCII.GetBytes(responseHeader.ToString());
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Flush();
        }

        // Returns null if the headers exceed MaxHeaderBytes.
        private static string? ReadHeaders(Stream stream)
        {
            StringBuilder headerCollector = new StringBuilder();
            byte[] buffer = new byte[1];
            while (stream.Read(buffer, 0, 1) > 0)
            {
                headerCollector.Append((char)buffer[0]);
                if (headerCollector.ToString().EndsWith("\r\n\r\n"))
                    break;
                if (headerCollector.Length >= MaxHeaderBytes)
                    return null;
            }
            return headerCollector.ToString();
        }

        private static int ParseContentLength(string headers)
        {
            foreach (var line in headers.Split("\r\n"))
            {
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                {
                    int.TryParse(line.Split(":")[1].Trim(), out int length);
                    return length;
                }
            }
            return 0;
        }
    }
}
