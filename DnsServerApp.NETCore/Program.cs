using DnsServerCore;
using System;
using System.Threading;

namespace DnsServerApp
{
    class Program
    {
        static void Main(string[] args)
        {
            string configFolder = null;

            if (args.Length == 1)
                configFolder = args[0];

            DnsWebService service = null;

            try
            {
                service = new DnsWebService(configFolder);
                service.Start();

                Console.WriteLine("Technitium DNS Server was started successfully.");
                Console.WriteLine("Using config folder: " + service.ConfigFolder);
                Console.WriteLine("");
                Console.WriteLine("");
                Console.WriteLine("Press [CTRL + C] to stop...");

                Thread main = Thread.CurrentThread;

                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e)
                {
                    e.Cancel = true;
                    main.Interrupt();
                };

                AppDomain.CurrentDomain.ProcessExit += delegate
                {
                    if (service != null)
                    {
                        Console.WriteLine("");
                        Console.WriteLine("Technitium DNS Server is stopping...");
                        service.Dispose();
                        service = null;
                        Console.WriteLine("Technitium DNS Server was stopped successfully.");
                    }
                };

                Thread.Sleep(Timeout.Infinite);
            }
            catch (ThreadInterruptedException)
            { }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                if (service != null)
                {
                    Console.WriteLine("");
                    Console.WriteLine("Technitium DNS Server is stopping...");
                    service.Dispose();
                    service = null;
                    Console.WriteLine("Technitium DNS Server was stopped successfully.");
                }
            }
        }
    }
}
