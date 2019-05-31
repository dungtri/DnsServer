using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using DnsServer.Core.Configuration;
using DnsServer.Core.IO;
using DnsServer.Core.Net;
using DnsServer.Core.Net.Dns;

namespace DnsServer.Core
{
    public class DnsService : IDisposable
    {
        private readonly IEnvVarReader _envVarReader;
        readonly string _currentVersion;

        readonly LogManager _log;
        StatsManager _stats;

        DnsServer _dnsServer;

        string _tlsCertificatePath;
        string _tlsCertificatePassword;
        Timer _tlsCertificateUpdateTimer;
        DateTime _tlsCertificateLastModifiedOn;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        volatile ServiceState _state = ServiceState.Stopped;

        Timer _blockListUpdateTimer;
        readonly List<Uri> _blockListUrls = new List<Uri>();
        DateTime _blockListLastUpdatedOn;
        const int BLOCK_LIST_UPDATE_AFTER_HOURS = 24;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_INTERVAL = 900000;
        const int BLOCK_LIST_UPDATE_RETRIES = 3;

        List<string> _configDisabledZones;

        private string _appName;

        public DnsService(IEnvVarReader envVarReader)
        {
            _log = new LogManager();

            _envVarReader = envVarReader;

            Assembly assembly = Assembly.GetEntryAssembly();
            AssemblyName assemblyName = assembly.GetName();
            _appName = assemblyName.Name;

            _currentVersion = assemblyName.Version.ToString();
            var configFolder = _envVarReader.Get(EnvVars.CONFIG_FOLDER);
            ConfigFolder = configFolder;

            if (ConfigFolder == null)
            {
                var appFolder = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                ConfigFolder = Path.Combine(appFolder, _appName);
            }

            if (!Directory.Exists(ConfigFolder))
                Directory.CreateDirectory(ConfigFolder);

            string blockListsFolder = Path.Combine(ConfigFolder, "blocklists");

            if (!Directory.Exists(blockListsFolder))
                Directory.CreateDirectory(blockListsFolder);
        }

        private bool _disposed = false;
        private int _totalZonesAllowed;
        private int _totalZonesBlocked;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                Stop();

                if (_dnsServer != null)
                    _dnsServer.Dispose();

                if (_log != null)
                    _log.Dispose();

                if (_stats != null)
                    _stats.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        private IPEndPoint GetRequestRemoteEndPoint(HttpListenerRequest request)
        {
            //this is due to mono NullReferenceException issue
            try
            {
                if (NetUtilities.IsPrivateIP(request.RemoteEndPoint.Address))
                {
                    //reverse proxy X-Real-IP header supported only when remote IP address is private

                    string xRealIp = request.Headers["X-Real-IP"];
                    if (!string.IsNullOrEmpty(xRealIp))
                    {
                        //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                        return new IPEndPoint(IPAddress.Parse(xRealIp), 0);
                    }
                }

                return request.RemoteEndPoint;
            }
            catch
            {
                return new IPEndPoint(IPAddress.Any, 0);
            }
        }

        private static void SendError(HttpListenerResponse response, Exception ex)
        {
            SendError(response, 500, ex.ToString());
        }

        private static void SendError(HttpListenerResponse response, int statusCode, string message = null)
        {
            try
            {
                string statusString = statusCode + " " + DnsServer.GetStatusString((HttpStatusCode)statusCode);
                byte[] buffer = Encoding.UTF8.GetBytes("<html><head><title>" + statusString + "</title></head><body><h1>" + statusString + "</h1>" + (message == null ? "" : "<p>" + message + "</p>") + "</body></html>");

                response.StatusCode = statusCode;
                response.ContentType = "text/html";
                response.ContentLength64 = buffer.Length;

                using (Stream stream = response.OutputStream)
                {
                    stream.Write(buffer, 0, buffer.Length);
                }
            }
            catch
            { }
        }

        private static void SendFile(HttpListenerResponse response, string path)
        {
            using (FileStream fS = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                response.ContentType = WebUtilities.GetContentType(path).MediaType;
                response.ContentLength64 = fS.Length;
                response.AddHeader("Cache-Control", "private, max-age=300");

                using (Stream stream = response.OutputStream)
                {
                    try
                    {
                        fS.CopyTo(stream);
                    }
                    catch (HttpListenerException)
                    {
                        //ignore this error
                    }
                }
            }
        }

        private void ExportAllowedZones(HttpListenerResponse response)
        {
            ICollection<Zone.ZoneInfo> zoneInfoList = _dnsServer.AllowedZoneRoot.ListAuthoritativeZones();

            response.ContentType = "text/plain";
            response.AddHeader("Content-Disposition", "attachment;filename=AllowedZones.txt");

            using (StreamWriter sW = new StreamWriter(new BufferedStream(response.OutputStream)))
            {
                foreach (Zone.ZoneInfo zoneInfo in zoneInfoList)
                    sW.WriteLine(zoneInfo.ZoneName);
            }
        }

        private void AllowZone(string domain)
        {
            _dnsServer.AllowedZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 60, new DnsResourceRecordData[] { new DnsSOARecord(_dnsServer.ServerDomain, "hostmaster." + _dnsServer.ServerDomain, 1, 28800, 7200, 604800, 600) });
        }

        private void BlockZone(string domain, Zone blockedZoneRoot, string blockListUrl)
        {
            blockedZoneRoot.SetRecords(new DnsResourceRecord[]
            {
                new DnsResourceRecord(domain, DnsResourceRecordType.SOA, DnsClass.IN, 60, new DnsSOARecord(_dnsServer.ServerDomain, "hostmaster." + _dnsServer.ServerDomain, 1, 28800, 7200, 604800, 600)),
                new DnsResourceRecord(domain, DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecord(IPAddress.Any)),
                new DnsResourceRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN, 60, new DnsAAAARecord(IPAddress.IPv6Any))
            });

            blockedZoneRoot.AddRecord(domain, DnsResourceRecordType.TXT, 60, new DnsTXTRecord("blockList=" + blockListUrl));
        }

        private void CreateZone(string domain)
        {
            _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.SOA, 14400, new DnsResourceRecordData[] { new DnsSOARecord(_dnsServer.ServerDomain, "hostmaster." + _dnsServer.ServerDomain, uint.Parse(DateTime.UtcNow.ToString("yyyyMMddHH")), 28800, 7200, 604800, 600) });
            _dnsServer.AuthoritativeZoneRoot.SetRecords(domain, DnsResourceRecordType.NS, 14400, new DnsResourceRecordData[] { new DnsNSRecord(_dnsServer.ServerDomain) });
        }

        private void LoadZoneFiles()
        {
            string[] zoneFiles = Directory.GetFiles(ConfigFolder, "*.zone");

            if (zoneFiles.Length == 0)
            {
                {
                    CreateZone("localhost");
                    _dnsServer.AuthoritativeZoneRoot.SetRecords("localhost", DnsResourceRecordType.A, 3600, new DnsResourceRecordData[] { new DnsARecord(IPAddress.Loopback) });
                    _dnsServer.AuthoritativeZoneRoot.SetRecords("localhost", DnsResourceRecordType.AAAA, 3600, new DnsResourceRecordData[] { new DnsAAAARecord(IPAddress.IPv6Loopback) });

                    SaveZoneFile("localhost");
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.Loopback, DnsClass.IN).Name;

                    CreateZone(prtDomain);
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });

                    SaveZoneFile(prtDomain);
                }

                {
                    string prtDomain = new DnsQuestionRecord(IPAddress.IPv6Loopback, DnsClass.IN).Name;

                    CreateZone(prtDomain);
                    _dnsServer.AuthoritativeZoneRoot.SetRecords(prtDomain, DnsResourceRecordType.PTR, 3600, new DnsResourceRecordData[] { new DnsPTRRecord("localhost") });

                    SaveZoneFile(prtDomain);
                }
            }
            else
            {
                foreach (string zoneFile in zoneFiles)
                {
                    try
                    {
                        LoadZoneFile(zoneFile);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to loaded zone file: " + zoneFile + "\r\n" + ex.ToString());
                    }
                }
            }
        }

        private void LoadZoneFile(string zoneFile)
        {
            using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
            {
                BinaryReader bR = new BinaryReader(fS);

                if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DZ")
                    throw new InvalidDataException("DnsServer zone file format is invalid.");

                switch (bR.ReadByte())
                {
                    case 1:
                        fS.Position = 0;
                        LoadZoneFileV1(fS);
                        break;

                    case 2:
                        {
                            int count = bR.ReadInt32();
                            DnsResourceRecord[] records = new DnsResourceRecord[count];

                            for (int i = 0; i < count; i++)
                                records[i] = new DnsResourceRecord(fS);

                            _dnsServer.AuthoritativeZoneRoot.SetRecords(records);
                        }
                        break;

                    case 3:
                        {
                            bool zoneDisabled = bR.ReadBoolean();
                            int count = bR.ReadInt32();

                            if (count > 0)
                            {
                                DnsResourceRecord[] records = new DnsResourceRecord[count];

                                for (int i = 0; i < count; i++)
                                {
                                    records[i] = new DnsResourceRecord(fS);
                                    records[i].Tag = new Zone.DnsResourceRecordInfo(new BinaryReader(fS));
                                }

                                _dnsServer.AuthoritativeZoneRoot.SetRecords(records);

                                if (zoneDisabled)
                                    _dnsServer.AuthoritativeZoneRoot.DisableZone(records[0].Name);
                            }
                        }
                        break;

                    default:
                        throw new InvalidDataException("DNS Zone file version not supported.");
                }
            }

            _log.Write("Loaded zone file: " + zoneFile);
        }

        private void LoadZoneFileV1(Stream s)
        {
            BincodingDecoder decoder = new BincodingDecoder(s, "DZ");

            switch (decoder.Version)
            {
                case 1:
                    ICollection<Bincoding> entries = decoder.DecodeNext().GetList();
                    DnsResourceRecord[] records = new DnsResourceRecord[entries.Count];

                    int i = 0;
                    foreach (Bincoding entry in entries)
                        records[i++] = new DnsResourceRecord(entry.GetValueStream());

                    _dnsServer.AuthoritativeZoneRoot.SetRecords(records);
                    break;

                default:
                    throw new IOException("DNS Zone file version not supported: " + decoder.Version);
            }
        }

        private void SaveZoneFile(string domain)
        {
            domain = domain.ToLower();
            DnsResourceRecord[] records = _dnsServer.AuthoritativeZoneRoot.GetAllRecords(domain, DnsResourceRecordType.ANY, true, true);
            if (records.Length == 0)
                throw new DnsServiceException("Zone '" + domain + "' was not found.");

            string authZone = records[0].Name.ToLower();

            if (Zone.DomainEquals(authZone, "resolver-associated-doh.arpa") || Zone.DomainEquals(authZone, "resolver-addresses.arpa"))
                return;

            using (MemoryStream mS = new MemoryStream())
            {
                //serialize zone
                BinaryWriter bW = new BinaryWriter(mS);

                bW.Write(Encoding.ASCII.GetBytes("DZ")); //format
                bW.Write((byte)3); //version

                bW.Write(_dnsServer.AuthoritativeZoneRoot.IsZoneDisabled(domain));
                bW.Write(records.Length);

                foreach (DnsResourceRecord record in records)
                {
                    record.WriteTo(mS);

                    Zone.DnsResourceRecordInfo rrInfo = record.Tag as Zone.DnsResourceRecordInfo;
                    if (rrInfo == null)
                        rrInfo = new Zone.DnsResourceRecordInfo(); //default info

                    rrInfo.WriteTo(bW);
                }

                //write to zone file
                mS.Position = 0;

                using (FileStream fS = new FileStream(Path.Combine(ConfigFolder, authZone + ".zone"), FileMode.Create, FileAccess.Write))
                {
                    mS.CopyTo(fS);
                }
            }

            _log.Write("Saved zone file for domain: " + domain);
        }

        private void DeleteZoneFile(string domain)
        {
            domain = domain.ToLower();

            File.Delete(Path.Combine(ConfigFolder, domain + ".zone"));

            _log.Write("Deleted zone file for domain: " + domain);
        }

        private void LoadBlockLists()
        {
            Zone blockedZoneRoot = new Zone(true);

            using (CountdownEvent countdown = new CountdownEvent(_blockListUrls.Count))
            {
                foreach (Uri blockListUrl in _blockListUrls)
                {
                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            LoadBlockListFile(blockedZoneRoot, state as Uri);
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }

                        countdown.Signal();

                    }, blockListUrl);
                }

                // TODO: Read list from environment settings
                //load custom blocked zone into new block zone
                //foreach (Zone.ZoneInfo zone in _customBlockedZoneRoot.ListAuthoritativeZones())
                //    BlockZone(zone.ZoneName, blockedZoneRoot, "custom");

                countdown.Wait();
            }

            //set new blocked zone
            _dnsServer.BlockedZoneRoot = blockedZoneRoot;
            _totalZonesBlocked = blockedZoneRoot.ListAuthoritativeZones().Count;

            _log.Write("DNS Server blocked zone loading finished successfully.");
        }

        private string GetBlockListFilePath(Uri blockListUrl)
        {
            using (HashAlgorithm hash = SHA256.Create())
            {
                return Path.Combine(ConfigFolder, "blocklists", BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(blockListUrl.AbsoluteUri))).Replace("-", "").ToLower());
            }
        }

        private void LoadBlockListFile(Zone blockedZoneRoot, Uri blockListUrl)
        {
            string blockListAbsoluteUrl = blockListUrl.AbsoluteUri;

            try
            {
                string blockListFilePath = GetBlockListFilePath(blockListUrl);
                int count = 0;

                _log.Write("DNS Server is loading blocked zone from: " + blockListAbsoluteUrl);

                using (FileStream fS = new FileStream(blockListFilePath, FileMode.Open, FileAccess.Read))
                {
                    //parse hosts file and populate block zone
                    StreamReader sR = new StreamReader(fS, true);

                    while (true)
                    {
                        string line = sR.ReadLine();
                        if (line == null)
                            break; //eof

                        line = line.TrimStart(' ', '\t');

                        if (line == "")
                            continue; //skip empty line

                        if (line.StartsWith("#"))
                            continue; //skip comment line

                        string firstWord = PopWord(ref line);
                        string secondWord = PopWord(ref line);

                        string strIpAddress = null;
                        string hostname;

                        if (secondWord == "")
                        {
                            hostname = firstWord;
                        }
                        else
                        {
                            strIpAddress = firstWord;
                            hostname = secondWord;
                        }

                        if (!DnsClient.IsDomainNameValid(hostname, false))
                            continue;

                        switch (hostname.ToLower())
                        {
                            case "":
                            case "localhost":
                            case "localhost.localdomain":
                            case "local":
                            case "broadcasthost":
                            case "ip6-localhost":
                            case "ip6-loopback":
                            case "ip6-localnet":
                            case "ip6-mcastprefix":
                            case "ip6-allnodes":
                            case "ip6-allrouters":
                            case "ip6-allhosts":
                                continue; //skip these hostnames
                        }

                        if (IPAddress.TryParse(hostname, out IPAddress host))
                            continue; //skip line when hostname is IP address

                        IPAddress ipAddress;

                        if (string.IsNullOrEmpty(strIpAddress) || !IPAddress.TryParse(strIpAddress, out ipAddress))
                            ipAddress = IPAddress.Any;

                        if (ipAddress.Equals(IPAddress.Any) || ipAddress.Equals(IPAddress.Loopback) || ipAddress.Equals(IPAddress.IPv6Any) || ipAddress.Equals(IPAddress.IPv6Loopback))
                        {
                            BlockZone(hostname, blockedZoneRoot, blockListAbsoluteUrl);
                            count++;
                        }
                    }
                }

                _log.Write("DNS Server blocked zone was loaded (" + count + " domains) from: " + blockListAbsoluteUrl);
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server failed to load block list from: " + blockListAbsoluteUrl + "\r\n" + ex.ToString());
            }
        }

        private void UpdateBlockLists()
        {
            bool success = false;

            foreach (Uri blockListUrl in _blockListUrls)
            {
                string blockListFilePath = GetBlockListFilePath(blockListUrl);
                string blockListDownloadFilePath = blockListFilePath + ".downloading";

                try
                {
                    int retries = 1;

                    while (true)
                    {
                        if (File.Exists(blockListDownloadFilePath))
                            File.Delete(blockListDownloadFilePath);

                        using (WebClientEx wC = new WebClientEx())
                        {
                            wC.Proxy = _dnsServer.Proxy;
                            wC.Timeout = 60000;

                            try
                            {
                                wC.DownloadFile(blockListUrl, blockListDownloadFilePath);
                            }
                            catch (WebException)
                            {
                                if (retries < BLOCK_LIST_UPDATE_RETRIES)
                                {
                                    retries++;
                                    continue;
                                }

                                throw;
                            }
                        }

                        if (File.Exists(blockListFilePath))
                            File.Delete(blockListFilePath);

                        File.Move(blockListDownloadFilePath, blockListFilePath);

                        success = true;
                        _log.Write("DNS Server successfully downloaded block list (" + WebUtilities.GetFormattedSize(new FileInfo(blockListFilePath).Length) + "): " + blockListUrl.AbsoluteUri);
                        break;
                    }
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server failed to download block list and will use previously downloaded file (if available): " + blockListUrl.AbsoluteUri + "\r\n" + ex.ToString());
                }
            }

            if (success)
            {
                //save last updated on time
                _blockListLastUpdatedOn = DateTime.UtcNow;

                // TODO: Save config here?

                // LoadBlockLists();
            }
        }

        private static string PopWord(ref string line)
        {
            if (line == "")
                return line;

            line = line.TrimStart(' ', '\t');

            int i = line.IndexOf(' ');

            if (i < 0)
                i = line.IndexOf('\t');

            string word;

            if (i < 0)
            {
                word = line;
                line = "";
            }
            else
            {
                word = line.Substring(0, i);
                line = line.Substring(i + 1);
            }

            return word;
        }

        private void StartBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer == null)
            {
                _blockListUpdateTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(BLOCK_LIST_UPDATE_AFTER_HOURS))
                            UpdateBlockLists();
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while updating block list.\r\n" + ex.ToString());
                    }

                }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, BLOCK_LIST_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer != null)
            {
                _blockListUpdateTimer.Dispose();
                _blockListUpdateTimer = null;
            }
        }

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer == null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    try
                    {
                        FileInfo fileInfo = new FileInfo(_tlsCertificatePath);

                        if (fileInfo.Exists && (fileInfo.LastWriteTimeUtc != _tlsCertificateLastModifiedOn))
                            LoadTlsCertificate(_tlsCertificatePath, _tlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while updating TLS Certificate: " + _tlsCertificatePath + "\r\n" + ex.ToString());
                    }

                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer != null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        private void LoadTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            FileInfo fileInfo = new FileInfo(tlsCertificatePath);

            if (!fileInfo.Exists)
                throw new ArgumentException("Tls certificate file does not exists: " + tlsCertificatePath);

            if (Path.GetExtension(tlsCertificatePath) != ".pfx")
                throw new ArgumentException("Tls certificate file must be PKCS #12 formatted with .pfx extension: " + tlsCertificatePath);

            X509Certificate2 certificate = new X509Certificate2(tlsCertificatePath, tlsCertificatePassword);

            if (!certificate.Verify())
                throw new ArgumentException("Tls certificate is invalid.");

            _dnsServer.Certificate = certificate;
            _tlsCertificateLastModifiedOn = fileInfo.LastWriteTimeUtc;

            _log.Write("DNS Server TLS certificate was loaded: " + tlsCertificatePath);
        }

        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException("DnsService");

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException($"{_appName} is already running.");

            _state = ServiceState.Starting;

            try
            {
                if (_stats == null)
                {
                    string statsFolder = Path.Combine(ConfigFolder, "stats");

                    if (!Directory.Exists(statsFolder))
                        Directory.CreateDirectory(statsFolder);

                    _stats = new StatsManager(_log);
                }

                /* Initialize DnsServer with Default configuration */
                _dnsServer = new DnsServer()
                {
                    StatsManager = _stats,
                    ServerDomain = Environment.MachineName.ToLower(),
                    AllowRecursion = true,
                    AllowRecursionOnlyForPrivateNetworks = true,
                };

                LoadEnvironmentSettings();

                LoadZoneFiles();

                // TODO: A quoi ca sert?
                if (_configDisabledZones != null)
                {
                    foreach (string domain in _configDisabledZones)
                    {
                        _dnsServer.AuthoritativeZoneRoot.DisableZone(domain);
                        SaveZoneFile(domain);
                    }
                }
                var blockListUri = new[] {
                    "https://dbl.oisd.nl/",
                    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
                    "https://tspprs.com/dl/crypto",
                    "https://tspprs.com/dl/tracking",
                    "https://tspprs.com/dl/spotify",
                    "https://raw.githubusercontent.com/CHEF-KOCH/Audio-fingerprint-pages/master/AudioFp.txt",
                    "https://raw.githubusercontent.com/CHEF-KOCH/Canvas-fingerprinting-pages/master/Canvas.txt",
                    "https://raw.githubusercontent.com/CHEF-KOCH/WebRTC-tracking/master/WebRTC.txt",
                    "https://raw.githubusercontent.com/CHEF-KOCH/CKs-FilterList/master/HOSTS/Game.txt",
                    "https://raw.githubusercontent.com/CHEF-KOCH/NSABlocklist/master/HOSTS",
                    "https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/AakList.txt",
                    "https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/ParsedBlacklists/Prebake-Obtrusive.txt",
                    "https://jasonhill.co.uk/pfsense/ytadblock.txt"
                }.Select(url => new Uri(url));

                _blockListUrls.AddRange(blockListUri);

                // UpdateBlockLists();

                _dnsServer.Start();

                _state = ServiceState.Running;

                _log.Write($"{_appName} was started successfully.");
                Console.WriteLine("Using config folder: " + ConfigFolder);
                Console.WriteLine("");
                Console.WriteLine("");
                Console.WriteLine("Press [CTRL + C] to stop...");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start DNS Web Service (v" + _currentVersion + ")\r\n" + ex.ToString());
                throw;
            }
        }

        private void LoadEnvironmentSettings()
        {
            var logEnabled = _envVarReader.Get(EnvVars.LOG_ENABLED) ?? "true";
            if (Convert.ToBoolean(logEnabled))
            {
                _dnsServer.LogManager = _log;
            }

            var logQueryEnabled = _envVarReader.Get(EnvVars.LOG_QUERY_ENABLED) ?? "true";
            if (Convert.ToBoolean(logQueryEnabled))
            {
                _dnsServer.QueryLogManager = _log;
            }

            var ipV6Enabled = _envVarReader.Get(EnvVars.IPV6_ENABLED) ?? "true";
            var ipAddresses = new List<IPAddress> { IPAddress.Any };
            if (Convert.ToBoolean(ipV6Enabled))
            {
                ipAddresses.Add(IPAddress.IPv6Any);
            }
            _dnsServer.LocalAddresses = ipAddresses.ToArray();
        }

        public void Stop()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            try
            {
                _dnsServer.Stop();

                StopBlockListUpdateTimer();
                StopTlsCertificateUpdateTimer();

                _state = ServiceState.Stopped;
            }
            catch (Exception ex)
            {
                _log.Write("Failed to stop DNS Web Service (v" + _currentVersion + ")\r\n" + ex.ToString());
                throw;
            }
        }

        public string ConfigFolder { get; }
    }
}
