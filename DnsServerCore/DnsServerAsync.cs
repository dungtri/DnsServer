using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DnsServer.Core.Net.Dns;
using DnsServer.Core.Net.Proxy;

namespace DnsServer.Core
{
    public class DnsServerAsync
    {
        private readonly List<UdpClient> _udpListeners = new List<UdpClient>();
        private readonly List<TcpListener> _tcpListeners = new List<TcpListener>();


        private readonly LogManager _log = new LogManager();


        readonly ConcurrentDictionary<DnsQuestionRecord, RecursiveQueryLock> _recursiveQueryLocks = new ConcurrentDictionary<DnsQuestionRecord, RecursiveQueryLock>(Environment.ProcessorCount * 64, Environment.ProcessorCount * 32);

        volatile ServiceState _state = ServiceState.Stopped;
        private X509Certificate2 _certificate;
        private Zone _blockedZoneRoot = new Zone(true);

        public IPAddress[] LocalAddresses { get; set; }

        public bool EnableDnsOverHttp { get; set; }

        public bool EnableDnsOverTls { get; set; }

        public bool EnableDnsOverHttps { get; set; }

        public bool IsDnsOverHttpsEnabled { get; private set; }

        public X509Certificate2 Certificate
        {
            get => _certificate;
            set
            {
                if (!value.HasPrivateKey)
                    throw new ArgumentException("Tls certificate does not contain private key.");

                _certificate = value;
            }
        }

        public Zone AuthoritativeZoneRoot { get; } = new Zone(true);

        public Zone AllowedZoneRoot { get; } = new Zone(true);

        public Zone BlockedZoneRoot
        {
            get => _blockedZoneRoot;
            set
            {
                if (value == null)
                    throw new ArgumentNullException();

                if (!value.IsAuthoritative)
                    throw new ArgumentException("Blocked zone must be authoritative.");

                _blockedZoneRoot = value;
                _blockedZoneRoot.ServerDomain = AuthoritativeZoneRoot.ServerDomain;
            }
        }

        internal DnsCache Cache { get; }

        public NetProxy Proxy { get; set; }

        public DnsTransportProtocol ForwarderProtocol { get; set; } = DnsTransportProtocol.Udp;

        public DnsTransportProtocol RecursiveResolveProtocol { get; set; } = DnsTransportProtocol.Udp;

        public int MaxStackCount { get; set; } = 10;

        public LogManager LogManager { get; set; }

        public LogManager QueryLogManager { get; set; }

        public StatsManager StatsManager { get; set; }


        public Task Start(CancellationToken cancellationToken)
        {
            //if (_disposed)
            //    throw new ObjectDisposedException("DnsServer");

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("DNS Server is already running.");

            foreach (var address in LocalAddresses)
            {
                var dnsIPEndPoint = new IPEndPoint(address, 53);
                BindUdpListener(dnsIPEndPoint, DnsTransportProtocol.Udp);
                BindTcpListener(dnsIPEndPoint, DnsTransportProtocol.Tcp);

                if (EnableDnsOverHttp)
                {
                    BindTcpListener(new IPEndPoint(address, 8053), DnsTransportProtocol.Https);
                }

                if (EnableDnsOverTls && _certificate != null)
                {
                    BindTcpListener(new IPEndPoint(address, 853), DnsTransportProtocol.Tcp);
                }

                if (EnableDnsOverHttps && _certificate != null)
                {
                    BindTcpListener(new IPEndPoint(address, 443), DnsTransportProtocol.Tcp);
                }
            }

            if (IsDnsOverHttpsEnabled)
            {
                string serverDomain = AuthoritativeZoneRoot.ServerDomain;

                AuthoritativeZoneRoot.SetRecords("resolver-associated-doh.arpa", DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(serverDomain, "hostmaster." + serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyyMMddHH")), 28800, 7200, 604800, 600) });
                AuthoritativeZoneRoot.SetRecords("resolver-associated-doh.arpa", DnsResourceRecordType.NS, 14400, new DnsResourceRecordData[] { new DnsNSRecord(serverDomain) });
                AuthoritativeZoneRoot.SetRecords("resolver-associated-doh.arpa", DnsResourceRecordType.TXT, 60, new DnsResourceRecordData[] { new DnsTXTRecord("https://" + serverDomain + "/dns-query{?dns}") });

                AuthoritativeZoneRoot.SetRecords("resolver-addresses.arpa", DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(serverDomain, "hostmaster." + serverDomain, uint.Parse(DateTime.UtcNow.ToString("yyyyMMddHH")), 28800, 7200, 604800, 600) });
                AuthoritativeZoneRoot.SetRecords("resolver-addresses.arpa", DnsResourceRecordType.NS, 14400, new DnsResourceRecordData[] { new DnsNSRecord(serverDomain) });
                AuthoritativeZoneRoot.SetRecords("resolver-addresses.arpa", DnsResourceRecordType.CNAME, 60, new DnsResourceRecordData[] { new DnsCNAMERecord(serverDomain) });
            }

            var tasks = _udpListeners.Select(listener => ReadUdpRequestAsync(listener, cancellationToken)).AsParallel().ToArray();
            return Task.WhenAll(tasks);
        }

        private async Task ReadUdpRequestAsync(UdpClient client, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult data = await client.ReceiveAsync();
                    var memoryStream = new MemoryStream(data.Buffer, 0, data.Buffer.Length, false);
                    var datagram = new DnsDatagram(memoryStream);
                    await ProcessUdpRequestAsync(client, datagram, data.RemoteEndPoint);
                }
                catch (SocketException ex)
                {
                    _log.Write(client.Client.RemoteEndPoint as IPEndPoint, DnsTransportProtocol.Udp, ex);
                    throw;
                }


            }
        }

        private async Task ProcessUdpRequestAsync(UdpClient udpListener, DnsDatagram datagram, IPEndPoint remoteEP)
        {
            try
            {
                //DnsDatagram response = ProcessQuery(datagram, remoteEP, DnsTransportProtocol.Udp);
                DnsDatagram response = null;

                //send response
                if (response != null)
                {
                    byte[] sendBuffer = new byte[512];
                    var sendBufferStream = new MemoryStream(sendBuffer);

                    try
                    {
                        response.WriteTo(sendBufferStream);
                    }
                    catch (NotSupportedException)
                    {
                        DnsHeader header = response.Header;
                        response = new DnsDatagram(new DnsHeader(header.Identifier, true, header.OPCODE, header.AuthoritativeAnswer, true, header.RecursionDesired, header.RecursionAvailable, header.AuthenticData, header.CheckingDisabled, header.RCODE, header.QDCOUNT, 0, 0, 0), response.Question, null, null, null);

                        sendBufferStream.Position = 0;
                        response.WriteTo(sendBufferStream);
                    }

                    await udpListener.SendAsync(sendBuffer, (int)sendBufferStream.Position, remoteEP);
                    QueryLogManager.Write(remoteEP, DnsTransportProtocol.Udp, datagram, response);

                    StatsManager.Update(response, remoteEP.Address);
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return; //server stopping

                QueryLogManager.Write(remoteEP, DnsTransportProtocol.Udp, datagram, null);
                LogManager.Write(remoteEP, DnsTransportProtocol.Udp, ex);
            }
        }

        private UdpClient BindUdpListener(IPEndPoint ipEndPoint, DnsTransportProtocol transportProtocol)
        {
            try
            {
                var udpListener = new UdpClient(ipEndPoint);

                #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    const uint IOC_IN = 0x80000000;
                    const uint IOC_VENDOR = 0x18000000;
                    const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                    udpListener.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
                }

                #endregion

                _log.Write(ipEndPoint, transportProtocol, "DNS Server was bound successfully.");
                return udpListener;
            }
            catch (SocketException ex)
            {
                _log.Write(ipEndPoint, transportProtocol, $"DNS Server failed to bind.\r\n{ex}");
                throw;
            }
        }

        private TcpListener BindTcpListener(IPEndPoint ipEndPoint, DnsTransportProtocol transportProtocol)
        {
            TcpListener tcpListener = new TcpListener(ipEndPoint);
            try
            {
                tcpListener.Start(100);
                return tcpListener;
            }
            catch (SocketException ex)
            {
                _log.Write(ipEndPoint, DnsTransportProtocol.Tcp, $"DNS Server failed to bind.\r\n{ex}");
                throw;
            }
        }
    }
}
