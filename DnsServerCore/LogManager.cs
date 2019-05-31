using System;
using System.IO;
using System.Net;
using DnsServer.Core.IO;
using DnsServer.Core.Net.Dns;

namespace DnsServer.Core
{
    public class LogManager : IDisposable
    {
        TextWriter _logOut = Console.Out;

        readonly object _logFileLock = new object();
        #region constructor

        public LogManager()
        {
            AppDomain.CurrentDomain.UnhandledException += delegate (object sender, UnhandledExceptionEventArgs e)
            {
                Write((Exception)e.ExceptionObject);
            };
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            lock (_logFileLock)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    if (_logOut != null)
                    {
                        Write("Logging stopped.");
                        _logOut.Dispose();
                    }
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private void Write(DateTime dateTime, string message)
        {
            _logOut.WriteLine("[" + dateTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC] " + message);
            _logOut.Flush();
        }

        #endregion

        #region static

        public static void DownloadLog(HttpListenerResponse response, string logFile, long limit)
        {
            using (FileStream fS = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                response.ContentType = "text/plain";
                response.AddHeader("Content-Disposition", "attachment;filename=" + Path.GetFileName(logFile));

                if ((limit > fS.Length) || (limit < 1))
                    limit = fS.Length;

                OffsetStream oFS = new OffsetStream(fS, 0, limit);

                using (Stream s = response.OutputStream)
                {
                    oFS.CopyTo(s);

                    if (fS.Length > limit)
                    {
                        byte[] buffer = System.Text.Encoding.UTF8.GetBytes("####___TRUNCATED___####");
                        s.Write(buffer, 0, buffer.Length);
                    }
                }
            }
        }

        #endregion

        #region public

        public void Write(Exception ex)
        {
            Write(ex.ToString());
        }

        public void Write(IPEndPoint ep, Exception ex)
        {
            Write(ep, ex.ToString());
        }

        public void Write(IPEndPoint ep, string message)
        {
            string ipInfo;

            if (ep == null)
                ipInfo = "";
            else if (ep.Address.IsIPv4MappedToIPv6)
                ipInfo = "[" + ep.Address.MapToIPv4().ToString() + ":" + ep.Port + "] ";
            else
                ipInfo = "[" + ep.ToString() + "] ";

            Write(ipInfo + message);
        }

        public void Write(IPEndPoint ep, DnsTransportProtocol protocol, Exception ex)
        {
            Write(ep, protocol, ex.ToString());
        }

        public void Write(IPEndPoint ep, DnsTransportProtocol protocol, DnsDatagram request, DnsDatagram response)
        {
            DnsQuestionRecord q = null;

            if (request.Header.QDCOUNT > 0)
                q = request.Question[0];

            string question;

            if (q == null)
                question = "MISSING QUESTION!";
            else
                question = "QNAME: " + q.Name + "; QTYPE: " + q.Type.ToString() + "; QCLASS: " + q.Class;

            string responseInfo;

            if (response == null)
            {
                responseInfo = " NO RESPONSE FROM SERVER!";
            }
            else
            {
                string answer;

                if (response.Header.ANCOUNT == 0)
                {
                    answer = "[]";
                }
                else
                {
                    answer = "[";

                    for (int i = 0; i < response.Answer.Length; i++)
                    {
                        if (i != 0)
                            answer += ", ";

                        answer += response.Answer[i].RDATA.ToString();
                    }

                    answer += "]";
                }

                responseInfo = " RCODE: " + response.Header.RCODE.ToString() + "; ANSWER: " + answer;
            }

            Write(ep, protocol, question + ";" + responseInfo);
        }

        public void Write(IPEndPoint ep, DnsTransportProtocol protocol, string message)
        {
            string ipInfo;

            if (ep == null)
                ipInfo = "";
            else if (ep.Address.IsIPv4MappedToIPv6)
                ipInfo = "[" + ep.Address.MapToIPv4().ToString() + ":" + ep.Port + "] ";
            else
                ipInfo = "[" + ep.ToString() + "] ";

            Write(ipInfo + "[" + protocol.ToString().ToUpper() + "] " + message);
        }

        public void Write(string message)
        {
            try
            {
                lock (_logFileLock)
                {
                    DateTime now = DateTime.UtcNow;

                    Write(now, message);
                }
            }
            catch
            { }
        }


        #endregion

    }
}
