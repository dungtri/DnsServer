using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DnsServer.Core.Net;
using DnsServer.Core.Net.Dns;
using DnsServer.Core.Net.Proxy;

namespace DnsServer.Core
{
    public class DnsServerAsync
    {
        private readonly List<UdpClient> _udpListeners = new List<UdpClient>();
        private readonly List<TcpListener> _tcpListeners = new List<TcpListener>();

        int _cachePrefetchEligibility = 2;
        int _cachePrefetchTrigger = 9;
        int _timeout = 2000;

        private readonly LogManager _log = new LogManager();

        NameServerAddress[] _forwarders;

        readonly ConcurrentDictionary<DnsQuestionRecord, RecursiveQueryLock> _recursiveQueryLocks = new ConcurrentDictionary<DnsQuestionRecord, RecursiveQueryLock>(Environment.ProcessorCount * 64, Environment.ProcessorCount * 32);

        volatile ServiceState _state = ServiceState.Stopped;
        private X509Certificate2 _certificate;
        private Zone _blockedZoneRoot = new Zone(true);
        private readonly Zone _cacheZoneRoot = new Zone(false);

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

        public bool PreferIPv6 { get; set; }

        public LogManager LogManager { get; set; }

        public LogManager QueryLogManager { get; set; }

        public StatsManager StatsManager { get; set; }


        public Task Start(CancellationToken cancellationToken)
        {
            //if (_disposed)
            //    throw new ObjectDisposedException("DnsServer");

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("DNS Server is already running.");

            _state = ServiceState.Starting;

            foreach (var address in LocalAddresses)
            {
                var dnsIPEndPoint = new IPEndPoint(address, 53);
                _udpListeners.Add(BindUdpListener(dnsIPEndPoint, DnsTransportProtocol.Udp));
                _tcpListeners.Add(BindTcpListener(dnsIPEndPoint, DnsTransportProtocol.Tcp));

                if (EnableDnsOverHttp)
                {
                    _tcpListeners.Add(BindTcpListener(new IPEndPoint(address, 8053), DnsTransportProtocol.Https));
                }

                if (EnableDnsOverTls && _certificate != null)
                {
                    _tcpListeners.Add(BindTcpListener(new IPEndPoint(address, 853), DnsTransportProtocol.Tcp));
                }

                if (EnableDnsOverHttps && _certificate != null)
                {
                    _tcpListeners.Add(BindTcpListener(new IPEndPoint(address, 443), DnsTransportProtocol.Tcp));
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

            cancellationToken.Register(() =>
            {
                _state = ServiceState.Stopping;

                foreach (var listener in _udpListeners)
                {
                    listener.Dispose();
                }

                foreach (var listener in _tcpListeners)
                {
                    listener.Stop();
                }

                _udpListeners.Clear();
                _tcpListeners.Clear();

                _state = ServiceState.Stopped;
            });

            _state = ServiceState.Running;

            _log.Write($"DNS Server was started successfully.");
            _log.Write("Press [CTRL + C] to stop...");

            return Task.WhenAll(tasks);
        }

        private async Task ReadUdpRequestAsync(UdpClient listener, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult data = await listener.ReceiveAsync();
                    var memoryStream = new MemoryStream(data.Buffer, 0, data.Buffer.Length, false);
                    var datagram = new DnsDatagram(memoryStream);
                    await ProcessUdpRequestAsync(listener, datagram, data.RemoteEndPoint);
                }
                catch (ObjectDisposedException) { }
                catch (SocketException ex)
                {
                    _log.Write(listener.Client.RemoteEndPoint as IPEndPoint, DnsTransportProtocol.Udp, ex);
                    throw;
                }
            }
        }

        private bool IsRecursionAllowed(EndPoint remoteEP)
        {
            switch (remoteEP.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                case AddressFamily.InterNetworkV6:
                    return NetUtilities.IsPrivateIP((remoteEP as IPEndPoint).Address);

                default:
                    return false;
            }
        }

        private DnsDatagram ProcessAuthoritativeQuery(DnsDatagram request, bool isRecursionAllowed)
        {
            DnsDatagram response = AuthoritativeZoneRoot.Query(request);
            response.Tag = "cacheHit";

            if (response.Header.RCODE == DnsResponseCode.NoError)
            {
                if (response.Answer.Length > 0)
                {
                    DnsResourceRecordType questionType = request.Question[0].Type;
                    DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                    if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                    {
                        //resolve cname record
                        List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                        responseAnswer.AddRange(response.Answer);

                        DnsDatagram lastResponse;
                        bool cacheHit = ("cacheHit".Equals(response.Tag));

                        while (true)
                        {
                            DnsDatagram cnameRequest = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, DnsClass.IN) }, null, null, null);

                            //query authoritative zone first
                            lastResponse = AuthoritativeZoneRoot.Query(cnameRequest);

                            if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                            {
                                //not found in auth zone
                                if (!isRecursionAllowed || !cnameRequest.Header.RecursionDesired)
                                    break; //break since no recursion allowed/desired

                                //do recursion
                                lastResponse = ProcessRecursiveQuery(cnameRequest);
                                cacheHit &= ("cacheHit".Equals(lastResponse.Tag));
                            }
                            else if ((lastResponse.Header.RCODE == DnsResponseCode.NoError) && (lastResponse.Answer.Length == 0) && (lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.NS))
                            {
                                //found delegated zone
                                if (!isRecursionAllowed || !cnameRequest.Header.RecursionDesired)
                                    break; //break since no recursion allowed/desired

                                //do recursive resolution using delegated authority name servers
                                NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(lastResponse, PreferIPv6);

                                lastResponse = ProcessRecursiveQuery(cnameRequest, nameServers);
                                cacheHit &= ("cacheHit".Equals(lastResponse.Tag));
                            }

                            //check last response
                            if ((lastResponse.Header.RCODE != DnsResponseCode.NoError) || (lastResponse.Answer.Length == 0))
                                break; //cannot proceed to resolve cname further

                            responseAnswer.AddRange(lastResponse.Answer);

                            lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                            if (lastRR.Type != DnsResourceRecordType.CNAME)
                                break; //cname was resolved
                        }

                        DnsResponseCode rcode;
                        DnsResourceRecord[] authority;
                        DnsResourceRecord[] additional;

                        if (lastResponse.Header.RCODE == DnsResponseCode.Refused)
                        {
                            rcode = DnsResponseCode.NoError;
                            authority = new DnsResourceRecord[] { };
                            additional = new DnsResourceRecord[] { };
                        }
                        else
                        {
                            rcode = lastResponse.Header.RCODE;

                            if (lastResponse.Header.AuthoritativeAnswer)
                            {
                                authority = lastResponse.Authority;
                                additional = lastResponse.Additional;
                            }
                            else
                            {
                                if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                                    authority = lastResponse.Authority;
                                else
                                    authority = new DnsResourceRecord[] { };

                                additional = new DnsResourceRecord[] { };
                            }
                        }

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, lastResponse.Header.AuthoritativeAnswer, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, rcode, 1, (ushort)responseAnswer.Count, (ushort)authority.Length, (ushort)additional.Length), request.Question, responseAnswer.ToArray(), authority, additional) { Tag = (cacheHit ? "cacheHit" : null) };
                    }
                }
                else if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.NS) && isRecursionAllowed)
                {
                    //do recursive resolution using response authority name servers
                    NameServerAddress[] nameServers = NameServerAddress.GetNameServersFromResponse(response, PreferIPv6);

                    return ProcessRecursiveQuery(request, nameServers);
                }
            }

            return response;
        }

        private DnsDatagram QueryCache(DnsDatagram request, bool serveStale)
        {
            DnsDatagram cacheResponse = _cacheZoneRoot.Query(request, serveStale);

            if (cacheResponse.Header.RCODE != DnsResponseCode.Refused)
            {
                if ((cacheResponse.Answer.Length > 0) || (cacheResponse.Authority.Length == 0) || (cacheResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                {
                    cacheResponse.Tag = "cacheHit";

                    return cacheResponse;
                }
            }

            return null;
        }

        private DnsDatagram RecursiveResolve(DnsDatagram request, NameServerAddress[] viaNameServers, bool cachePrefetchOperation, bool cacheRefreshOperation)
        {
            if (!cachePrefetchOperation && !cacheRefreshOperation)
            {
                //query cache zone to see if answer available
                DnsDatagram cacheResponse = QueryCache(request, false);
                if (cacheResponse != null)
                {
                    if (_cachePrefetchTrigger > 0)
                    {
                        //inspect response TTL values to decide if prefetch trigger is needed
                        foreach (DnsResourceRecord answer in cacheResponse.Answer)
                        {
                            if ((answer.OriginalTtlValue > _cachePrefetchEligibility) && (answer.TtlValue < _cachePrefetchTrigger))
                            {
                                //trigger prefetch in worker thread
                                ThreadPool.QueueUserWorkItem(delegate (object state)
                                {
                                    try
                                    {
                                        RecursiveResolve(request, viaNameServers, true, false);
                                    }
                                    catch (Exception ex)
                                    {
                                        LogManager log = LogManager;
                                        if (log != null)
                                            log.Write(ex);
                                    }
                                });

                                break;
                            }
                        }
                    }

                    return cacheResponse;
                }
            }

            //recursion with locking
            RecursiveQueryLock newLockObj = new RecursiveQueryLock();
            RecursiveQueryLock actualLockObj = _recursiveQueryLocks.GetOrAdd(request.Question[0], newLockObj);

            if (actualLockObj.Equals(newLockObj))
            {
                //got lock so question not being resolved; do recursive resolution in worker thread
                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    DnsDatagram response = null;
                    const int retries = 2;

                    try
                    {
                        if ((viaNameServers == null) && (_forwarders != null))
                        {
                            
                            //use forwarders
                            //refresh forwarder IPEndPoint if stale
                            foreach (NameServerAddress nameServerAddress in _forwarders)
                            {
                                if (nameServerAddress.IsIPEndPointStale && (Proxy == null)) //recursive resolve name server when proxy is null else let proxy resolve it
                                    nameServerAddress.RecursiveResolveIPAddress(Cache, Proxy, PreferIPv6, RecursiveResolveProtocol, retries, _timeout, RecursiveResolveProtocol);
                            }

                            //query forwarders and update cache
                            DnsClient dnsClient = new DnsClient(_forwarders);

                            dnsClient.Proxy = Proxy;
                            dnsClient.PreferIPv6 = PreferIPv6;
                            dnsClient.Protocol = ForwarderProtocol;
                            dnsClient.Retries = retries;
                            dnsClient.Timeout = _timeout;
                            dnsClient.RecursiveResolveProtocol = RecursiveResolveProtocol;

                            response = dnsClient.Resolve(request.Question[0]);

                            Cache.CacheResponse(response);
                        }
                        else
                        {
                            //recursive resolve and update cache
                            response = DnsClient.RecursiveResolve(request.Question[0], viaNameServers, (cachePrefetchOperation || cacheRefreshOperation ? new ResolverPrefetchDnsCache(_cacheZoneRoot, request.Question[0]) : Cache), Proxy, PreferIPv6, RecursiveResolveProtocol, retries, _timeout, RecursiveResolveProtocol, MaxStackCount);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager log = LogManager;
                        if (log != null)
                        {
                            string nameServers = null;

                            if (viaNameServers != null)
                            {
                                foreach (NameServerAddress nameServer in viaNameServers)
                                {
                                    if (nameServers == null)
                                        nameServers = nameServer.ToString();
                                    else
                                        nameServers += ", " + nameServer.ToString();
                                }
                            }

                            log.Write("DNS Server recursive resolution failed for QNAME: " + request.Question[0].Name + "; QTYPE: " + request.Question[0].Type.ToString() + "; QCLASS: " + request.Question[0].Class.ToString() + (nameServers == null ? "" : "; Name Servers: " + nameServers) + ";\r\n" + ex.ToString());
                        }

                        //fetch stale record and reset expiry
                        {
                            DnsDatagram cacheResponse = QueryCache(request, true);
                            if (cacheResponse != null)
                            {
                                foreach (DnsResourceRecord record in cacheResponse.Answer)
                                {
                                    if (record.IsStale)
                                        record.ResetExpiry(30); //reset expiry by 30 seconds so that resolver tries again only after 30 seconds as per draft-ietf-dnsop-serve-stale-04
                                }

                                response = cacheResponse;
                            }
                        }
                    }
                    finally
                    {
                        //remove question lock
                        if (_recursiveQueryLocks.TryRemove(request.Question[0], out RecursiveQueryLock lockObj))
                        {
                            //pulse all waiting threads
                            lock (lockObj)
                            {
                                lockObj.SetComplete(response);
                                Monitor.PulseAll(lockObj);
                            }
                        }
                    }
                });
            }

            //request is being recursively resolved by worker thread

            if (cachePrefetchOperation)
                return null; //return null as prefetch worker thread does not need valid response and thus does not need to wait

            bool timeout = false;

            //wait till short timeout or pulse signal
            lock (actualLockObj)
            {
                if (!actualLockObj.Complete)
                    timeout = !Monitor.Wait(actualLockObj, _timeout - 200); //1.8 sec wait with default client timeout as 2 sec as per draft-ietf-dnsop-serve-stale-04
            }

            if (timeout)
            {
                //query cache zone to return stale answer (if available) as per draft-ietf-dnsop-serve-stale-04
                {
                    DnsDatagram cacheResponse = QueryCache(request, true);
                    if (cacheResponse != null)
                        return cacheResponse;
                }

                //wait till timeout or pulse signal for some more time before responding as ServerFailure
                //this is required since, quickly returning ServerFailure results in clients giving up lookup attempt early causing DNS error messages in web browsers
                timeout = false;

                lock (actualLockObj)
                {
                    if (!actualLockObj.Complete)
                        timeout = !Monitor.Wait(actualLockObj, _timeout + 200);
                }

                if (!timeout)
                {
                    if (actualLockObj.Response != null)
                        return actualLockObj.Response;
                }
            }
            else
            {
                if (actualLockObj.Response != null)
                    return actualLockObj.Response;
            }

            //no response available in cache so respond with ServerFailure
            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.ServerFailure, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
        }


        private DnsDatagram ProcessRecursiveQuery(DnsDatagram request, NameServerAddress[] viaNameServers = null, bool cacheRefreshOperation = false)
        {
            DnsDatagram response = RecursiveResolve(request, viaNameServers, false, cacheRefreshOperation);

            DnsResourceRecord[] authority;
            DnsResourceRecord[] additional;

            if (response.Answer.Length > 0)
            {
                DnsResourceRecordType questionType = request.Question[0].Type;
                DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                {
                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    responseAnswer.AddRange(response.Answer);

                    DnsDatagram lastResponse;
                    bool cacheHit = ("cacheHit".Equals(response.Tag));
                    int queryCount = 0;

                    while (true)
                    {
                        DnsQuestionRecord question = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, questionType, DnsClass.IN);

                        lastResponse = RecursiveResolve(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null), null, false, cacheRefreshOperation);
                        cacheHit &= ("cacheHit".Equals(lastResponse.Tag));

                        if (lastResponse.Answer.Length == 0)
                            break;

                        responseAnswer.AddRange(lastResponse.Answer);

                        lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                        if (lastRR.Type == questionType)
                            break;

                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                            throw new DnsServerException("Invalid response received from DNS server.");

                        queryCount++;
                        const int MAX_HOPS = 16;
                        if (queryCount > MAX_HOPS)
                            throw new DnsServerException("Recursive resolution exceeded max hops.");
                    }

                    if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                        authority = lastResponse.Authority;
                    else
                        authority = new DnsResourceRecord[] { };

                    if ((response.Additional.Length > 0) && (request.Question[0].Type == DnsResourceRecordType.MX))
                        additional = response.Additional;
                    else
                        additional = new DnsResourceRecord[] { };

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, lastResponse.Header.RCODE, 1, (ushort)responseAnswer.Count, (ushort)authority.Length, (ushort)additional.Length), request.Question, responseAnswer.ToArray(), authority, additional) { Tag = (cacheHit ? "cacheHit" : null) };
                }
            }

            if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                authority = response.Authority;
            else
                authority = new DnsResourceRecord[] { };

            if ((response.Additional.Length > 0) && (request.Question[0].Type == DnsResourceRecordType.MX))
                additional = response.Additional;
            else
                additional = new DnsResourceRecord[] { };

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, response.Header.RCODE, 1, (ushort)response.Answer.Length, (ushort)authority.Length, (ushort)additional.Length), request.Question, response.Answer, authority, additional) { Tag = response.Tag };
        }

        internal DnsDatagram ProcessQuery(DnsDatagram request, EndPoint remoteEP, DnsTransportProtocol protocol)
        {
            if (request.Header.IsResponse)
                return null;

            bool isRecursionAllowed = IsRecursionAllowed(remoteEP);

            switch (request.Header.OPCODE)
            {
                case DnsOpcode.StandardQuery:
                    if ((request.Question.Length != 1) || (request.Question[0].Class != DnsClass.IN))
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);

                    switch (request.Question[0].Type)
                    {
                        case DnsResourceRecordType.IXFR:
                        case DnsResourceRecordType.AXFR:
                        case DnsResourceRecordType.MAILB:
                        case DnsResourceRecordType.MAILA:
                            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
                    }

                    try
                    {
                        //query authoritative zone
                        DnsDatagram authoritativeResponse = ProcessAuthoritativeQuery(request, isRecursionAllowed);

                        if ((authoritativeResponse.Header.RCODE != DnsResponseCode.Refused) || !request.Header.RecursionDesired || !isRecursionAllowed)
                            return authoritativeResponse;

                        //query blocked zone
                        DnsDatagram blockedResponse = _blockedZoneRoot.Query(request);

                        if (blockedResponse.Header.RCODE != DnsResponseCode.Refused)
                        {
                            //query allowed zone
                            DnsDatagram allowedResponse = AllowedZoneRoot.Query(request);

                            if (allowedResponse.Header.RCODE == DnsResponseCode.Refused)
                            {
                                //request domain not in allowed zone

                                if (blockedResponse.Header.RCODE == DnsResponseCode.NameError)
                                {
                                    DnsResourceRecord[] answer;
                                    DnsResourceRecord[] authority;

                                    switch (blockedResponse.Question[0].Type)
                                    {
                                        case DnsResourceRecordType.A:
                                            answer = new DnsResourceRecord[] { new DnsResourceRecord(blockedResponse.Question[0].Name, DnsResourceRecordType.A, blockedResponse.Question[0].Class, 60, new DnsARecord(IPAddress.Any)) };
                                            authority = new DnsResourceRecord[] { };
                                            break;

                                        case DnsResourceRecordType.AAAA:
                                            answer = new DnsResourceRecord[] { new DnsResourceRecord(blockedResponse.Question[0].Name, DnsResourceRecordType.AAAA, blockedResponse.Question[0].Class, 60, new DnsAAAARecord(IPAddress.IPv6Any)) };
                                            authority = new DnsResourceRecord[] { };
                                            break;

                                        default:
                                            answer = blockedResponse.Answer;
                                            authority = blockedResponse.Authority;
                                            break;
                                    }

                                    blockedResponse = new DnsDatagram(new DnsHeader(blockedResponse.Header.Identifier, true, blockedResponse.Header.OPCODE, false, false, blockedResponse.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, blockedResponse.Header.QDCOUNT, (ushort)answer.Length, (ushort)authority.Length, 0), blockedResponse.Question, answer, authority, null);
                                }

                                //return blocked response
                                blockedResponse.Tag = "blocked";
                                return blockedResponse;
                            }
                        }

                        //do recursive query
                        return ProcessRecursiveQuery(request);
                    }
                    catch (Exception ex)
                    {
                        LogManager log = LogManager;
                        if (log != null)
                            log.Write(remoteEP as IPEndPoint, protocol, ex);

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.ServerFailure, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
                    }

                default:
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, request.Header.OPCODE, false, false, request.Header.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Header.QDCOUNT, 0, 0, 0), request.Question, null, null, null);
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
