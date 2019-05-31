using System;
using System.Threading;
using System.Threading.Tasks;
using DnsServer.Core;
using DnsServer.Core.Configuration;

namespace DnsServerApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            DnsService service = null;
            IEnvVarReader envVarReader = new EnvVarReader();
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            try
            {
                
                service = new DnsService(envVarReader);
                service.Start();

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
