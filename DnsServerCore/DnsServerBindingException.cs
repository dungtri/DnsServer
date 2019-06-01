using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using DnsServer.Core.Net.Dns;

namespace DnsServer.Core
{
    public class DnsServerBindingException : Exception
    {
        public IPEndPoint IPEndPoint { get; }
        public DnsTransportProtocol TransportProtocol { get; }

        public DnsServerBindingException(IPEndPoint endPoint, DnsTransportProtocol transportProtocol)
        {
            IPEndPoint = endPoint;
            TransportProtocol = transportProtocol;
        }
    }
}
