using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace HTTPS
{

    public class HTTPS
    {
        /// <summary>
        /// Https port
        /// </summary>
        public int Port = 443;

        public string UserAgent = "BouncyCastleHttpsClient/0.0.1 AWolf.net";

        public string Version = "HTTP/1.1";

        /// <summary>
        /// Read from tls stream timeout
        /// </summary>
        public uint Timeout = 30;

        /// <summary>
        /// Ignore the exception on no close notification
        /// </summary>
        public bool IgnoreNoCloseNotifyException = true;

        public bool Keepalive = false;

        public Encoding Encode = Encoding.ASCII;

        protected Dictionary<string, string> _requestHeaders = null;
        protected Dictionary<string, string> _responseHeaders = null;

        public static class ContentType
        {
            public const string Json = "application/json";
        }

#if false
        public string PostRaw(Uri uri, Dictionary<string, string> headers, string payload, string MediaType)
        {
            string host = uri.Host;
            string path = uri.AbsolutePath;

            List<byte> buffer = new List<byte>();

            StringBuilder hdr = new StringBuilder();
            hdr.AppendLine($"POST {path} {Version}");
            hdr.AppendLine($"Host: {host}");

            foreach (KeyValuePair<string, string> header in headers)
            {
                hdr.AppendLine($"{header.Key}: {header.Value}");
            }

            hdr.AppendLine($"Content-Type: {MediaType}");
            hdr.AppendLine("Connection: close");
            hdr.AppendLine($"Content-Length: {payload.Length}");
            hdr.AppendLine();
            hdr.AppendLine(payload);

            var dataToSend = Encode.GetBytes(hdr.ToString());


            using (var client = new TcpClient(host, Port))
            {
                SecureRandom sr = new SecureRandom();
                var cl = new Utils.HTTPS.TlsClient();
                var protocol = new TlsClientProtocol(client.GetStream(), sr);
                protocol.Connect(cl);

                using (var stream = protocol.Stream)
                {

                    stream.Write(dataToSend, 0, dataToSend.Length);

                    bool EndOfStream = false;
                    DateTime timeout = DateTime.UtcNow.AddSeconds(Timeout);
                    while (DateTime.UtcNow < timeout && !EndOfStream)
                    {
                        Application.DoEvents();
                        //Task.Delay(100);

                        while (stream.CanRead)
                        {
                            int b;
                            try
                            {
                                b = stream.ReadByte();
                                if (b < 0)
                                {
                                    break;
                                }
                                else
                                {
                                    buffer.Add((byte)b);
                                }
                            }
                            catch (Org.BouncyCastle.Crypto.Tls.TlsNoCloseNotifyException ex)
                            {
                                string message = ex.Message;
                                Utils.Log.I(message);
                                if (!IgnoreNoCloseNotifyException)
                                {
                                    throw new ReadOnClosedTlsStreamException(message);
                                }
                                else
                                {
                                    EndOfStream = true;
                                    break;
                                }
                            }
                            catch (Exception ex)
                            {
                                throw ex;
                            }

                        }
                    }

                    if (DateTime.UtcNow > timeout)
                    {
                        Utils.Log.D("PostRaw", "Waiting for stream timeout");
                        throw new TimeoutException("Waiting for stream timeout");
                    }


                    string response = Encode.GetString(buffer.ToArray(), 0, buffer.Count);



                    Utils.Log.D("Response:", response);

                    return response;
                }


            }

        }

#endif
        public T PostRaw<T>(Uri uri, Dictionary<string, string> headers, string payload, string MediaType)
        {
            headers.Add("Content-Type", MediaType);

            HttpResponse _response = Request(HttpMethod.Post, uri, headers, payload);
            //Utils.Log.D<HttpResponse>("Response", _response);
            if (_response.StatusCode == HttpStatusCode.OK)
            {
                return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(_response.Content);
            }
            else
            {
                throw new HttpException(_response.StatusCode, _response.Status);
            }


            //HttpRequestMessage httpRequest = new HttpRequestMessage
            //{
            //    Method = HttpMethod.Post,
            //    RequestUri = uri,
            //    Content = new StringContent(payload)
            //};

            //httpRequest.Content.Headers.ContentType = new MediaTypeHeaderValue(MediaType);

            //foreach (KeyValuePair<string, string> header in headers)
            //{
            //    httpRequest.Headers.Add(header.Key, header.Value);
            //}

            //makeHttpRequest(httpRequest);

            //return _response.GetResponseModel<T>();
        }



        public void AddHeader(string header, string value)
        {

        }

        public HttpResponse Request(HttpMethod httpMethod, Uri uri, Dictionary<string, string> requestHeaders, string payload)
        {
            string host = uri.Host;
            string path = uri.AbsolutePath;

            List<byte> buffer = new List<byte>();


            StringBuilder content = new StringBuilder();
            content.AppendLine($"{httpMethod.ToString()} {path} {Version}");
            content.AppendLine($"Host: {host}");

            if (requestHeaders.ContainsKey("Content-Length"))
            {
                throw new HttpHeadersArgumentException("\"Content-Length\" should not be setted");
            }

            if (requestHeaders.ContainsKey("User-Agent"))
            {
                content.AppendLine($"User-Agent: {requestHeaders["User-Agent"]}");
                requestHeaders.Remove("User-Agent");
            }
            else
            {
                content.AppendLine($"User-Agent: {UserAgent}");
            }

            if (requestHeaders.ContainsKey("Connection"))
            {
                content.AppendLine($"Connection: {requestHeaders["Connection"]}");
                requestHeaders.Remove("Connection");
            }
            else
            {
                if (Keepalive)
                {
                    content.AppendLine("Connection: keep-alive");
                }
                else
                {
                    content.AppendLine("Connection: close");
                }
            }


            foreach (KeyValuePair<string, string> header in requestHeaders)
            {
                content.AppendLine($"{header.Key}: {header.Value}");
            }

            if (!string.IsNullOrWhiteSpace(payload))
            {
                content.AppendLine($"Content-Length: {payload.Length}");
                content.AppendLine();
                content.AppendLine(payload);
            }

            //Utils.Log.D("Data send to TLS Channel", content.ToString());

            byte[] bytesReceived;

            using (TcpClient tcpClient = new TcpClient(host, Port))
            {
                SecureRandom secureRandom = new SecureRandom();
                TlsClient tlsClient = new HTTPS.TlsClient();


                Stream tcpStream = tcpClient.GetStream();

                bytesReceived = FetchDataFromStreamWithTls(tcpStream, secureRandom, tlsClient, Encode.GetBytes(content.ToString()), Timeout, IgnoreNoCloseNotifyException);
            }

            string httpRawData = Encode.GetString(bytesReceived, 0, bytesReceived.Length);

            //Utils.Log.D("Data receive from TLS Channel", httpRawData);

            string httpVersion;
            string httpStatus;
            int httpCode = CheckHttpProtocol(httpRawData, out httpVersion, out httpStatus);

            HttpResponse httpResponse = new HttpResponse()
            {
                HttpVersion = httpVersion,
                StatusCode = (HttpStatusCode)httpCode,
                Status = httpStatus,
                RawData = bytesReceived,
            };

            int start = httpRawData.IndexOf("\r\n");
            int split = httpRawData.IndexOf("\r\n\r\n");

            string[] headersRaw = httpRawData.Substring(start, split - start).Trim().Split('\n');
            httpResponse.Content = httpRawData.Substring(split).Trim();

            httpResponse.Headers = new Dictionary<string, string>();
            foreach (string header in headersRaw)
            {
                int offset = header.IndexOf(':');

                string key = header.Substring(0, offset).Trim();
                string value = header.Substring(offset + 1).Trim();
                httpResponse.Headers.Add(key, value);
            }

            return httpResponse;
        }

        public byte[] FetchDataFromStreamWithTls(Stream stream, SecureRandom secureRandom, TlsClient tlsClient, byte[] dataToSend, uint timeout, bool ignoreStreamClosedException)
        {
            List<byte> buffer = new List<byte>();

            var protocol = new TlsClientProtocol(stream, secureRandom);
            try
            {
                protocol.Connect(tlsClient);
            }
            catch (Org.BouncyCastle.Crypto.Tls.TlsFatalAlert ex)
            {
                throw new TlsException(ex.Message);
            }


            using (var tlsStream = protocol.Stream)
            {

                tlsStream.Write(dataToSend, 0, dataToSend.Length);

                bool EndOfStream = false;
                DateTime endTime = DateTime.UtcNow.AddSeconds(timeout);
                while (DateTime.UtcNow < endTime && !EndOfStream)
                {
                    //Task.Delay(100);

                    while (tlsStream.CanRead)
                    {
                        int b;
                        try
                        {
                            b = tlsStream.ReadByte();
                            if (b < 0)
                            {
                                break;
                            }
                            else
                            {
                                buffer.Add((byte)b);
                            }
                        }
                        catch (Org.BouncyCastle.Crypto.Tls.TlsNoCloseNotifyException ex)
                        {
                            string message = ex.Message;
                            if (!IgnoreNoCloseNotifyException)
                            {
                                throw new ReadOnClosedTlsStreamException(message);
                            }
                            else
                            {
                                EndOfStream = true;
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            throw ex;
                        }

                    }
                }

                if (DateTime.UtcNow > endTime)
                {
                    throw new TimeoutException("Waiting for stream timeout");
                }

            }

            return buffer.ToArray();

        }

        //private List<byte> ReadFromStream(Stream stream, bool ignoreStreamClosedException, out bool endOfStream)
        //{
        //    List<byte> buffer = null;

        //    while (stream.CanRead)
        //    {
        //        int b;
        //        try
        //        {
        //            Console.WriteLine($"start to read");
        //            b = stream.ReadByte();
        //            Console.WriteLine($"read byte:{b}");
        //            if (b < 0)
        //            {
        //                endOfStream = true;
        //                break;
        //            }
        //            else
        //            {
        //                if (buffer == null)
        //                {
        //                    buffer = new List<byte>();
        //                }

        //                buffer.Add((byte)b);
        //            }
        //            Console.WriteLine($"read {buffer.Count}");
        //        }
        //        catch (Org.BouncyCastle.Crypto.Tls.TlsNoCloseNotifyException ex)
        //        {
        //            string message = ex.Message;
        //            Utils.Log.I(message);
        //            if (!ignoreStreamClosedException)
        //            {
        //                throw new ReadOnClosedTlsStreamException(message);
        //            }
        //            else
        //            {
        //                endOfStream = true;
        //                break;
        //            }
        //        }
        //        catch (Exception ex)
        //        {
        //            throw ex;
        //        }

        //    }

        //    endOfStream = false;
        //    return buffer;
        //}

        private int CheckHttpProtocol(string response, out string httpVersion, out string httpStatus)
        {
            string httpProtocolHeader = Regex.Match(response, @"^HTTP/1.[0-1] [1-5][0-9][0-9] .+").ToString();
            if (string.IsNullOrWhiteSpace(httpProtocolHeader))
            {
                throw new HttpProtocolException("Http protocol mismatch");
            }


            httpVersion = Regex.Match(httpProtocolHeader, @"^HTTP/1.[0-1]").ToString().Trim();
            if (!Version.Equals(httpVersion))
            {
                throw new HttpVersionMismatchException($"Expected {Version} but responsed {httpVersion}");
            }

            string httpCode = Regex.Match(httpProtocolHeader, @"[1-5][0-9][0-9]").ToString().Trim();
            httpStatus = Regex.Match(httpProtocolHeader, @"\s[A-Za-z\s]+$").ToString().Trim();

            return int.Parse(httpCode);
        }

        public class HttpResponse
        {
            public string HttpVersion { set; get; }
            public HttpStatusCode StatusCode { set; get; }

            public string Status { set; get; }
            public string Content { set; get; }

            public Dictionary<string, string> Headers { set; get; }

            public byte[] RawData { set; get; }
        }

        public class TimeoutException : Exception
        {
            public TimeoutException(string Message) : base(Message)
            {

            }
        }

        public class ReadOnClosedTlsStreamException : Exception
        {
            public ReadOnClosedTlsStreamException(string Message) : base(Message)
            {

            }
        }

        public class HttpHeadersArgumentException : Exception
        {
            public HttpHeadersArgumentException(string Message) : base(Message)
            {

            }
        }

        public class HttpProtocolException : Exception
        {
            public HttpProtocolException(string Message) : base(Message)
            {

            }
        }

        public class HttpVersionMismatchException : Exception
        {
            public HttpVersionMismatchException(string Message) : base(Message)
            {

            }
        }

        public class HttpException : Exception
        {
            private HttpStatusCode _code;
            public HttpException(HttpStatusCode Code, string Message) : base(Message)
            {
                _code = Code;
            }
        }

        public class TlsException : Exception
        {
            public TlsException(string Message) : base(Message)
            {

            }
        }

        public class TlsClient : DefaultTlsClient
        {
            public override Org.BouncyCastle.Crypto.Tls.TlsAuthentication GetAuthentication()
            {
                return new TlsAuthentication();
            }
        }

        public class TlsAuthentication : Org.BouncyCastle.Crypto.Tls.TlsAuthentication
        {
            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest) { return null; }

            public void NotifyServerCertificate(Certificate serverCertificate) { }
        }
    }
}
