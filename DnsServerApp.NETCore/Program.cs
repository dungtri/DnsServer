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
            IEnvVarReader envVarReader = new EnvVarReader();
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            try
            {
                
                var service = new DnsService(envVarReader);
                
                Console.CancelKeyPress += (sender, eventArgs) =>
                {
                    Console.WriteLine("Cancel event triggered");
                    cancellationTokenSource
                        .Cancel(false);

                    eventArgs.Cancel = true;
                };

                await service.Start(cancellationTokenSource.Token).ConfigureAwait(false);
                service.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }

            Console.WriteLine("DNS Server was stopped successfully.");
        }
    }
}
