using DnsServerCore;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DnsServerApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string configFolder = null;

            if (args.Length == 1)
                configFolder = args[0];

            DnsService service = null;
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            try
            {
                service = new DnsService(configFolder);
                service.Start();

                Console.WriteLine("Technitium DNS Server was started successfully.");
                Console.WriteLine("Using config folder: " + service.ConfigFolder);
                Console.WriteLine("");
                Console.WriteLine("");
                Console.WriteLine("Press [CTRL + C] to stop...");

                Console.CancelKeyPress += delegate
                {
                    cancellationTokenSource.Cancel(false);
                };

                while (true)
                {
                    await Task.Delay(1000, cancellationTokenSource.Token);

                    if (cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        break;
                    }
                }
            }
            catch (ThreadInterruptedException) { }
            catch (TaskCanceledException) { }
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
