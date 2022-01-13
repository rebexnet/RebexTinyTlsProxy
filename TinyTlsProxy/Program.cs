using System;
using System.Threading;
using Rebex.Security.Cryptography;

namespace Rebex.Proxy
{
	public class Program
	{
		static void Main(string[] args)
		{
			// get your Rebex trial license key at https://www.rebex.net/support/trial/
			// and replace the following line of code:
			Rebex.Licensing.Key = Environment.GetEnvironmentVariable("REBEX_KEY");

			var config = new Arguments(args);
			if (config.Error.Length > 0)
			{
				ShowHelp(config.Error.ToString());
				return;
			}

			if (config.ShowHelp)
			{
				ShowHelp(errors: null);
			}

			// register NIST and Brainpool curves
			AsymmetricKeyAlgorithm.Register(EllipticCurveAlgorithm.Create);

			// register Curve25519
			AsymmetricKeyAlgorithm.Register(Curve25519.Create);

			using (var proxy = new TlsProxy(config.Bindings))
			{
				proxy.Timeout = config.Timeout * 1000;
				proxy.LogWriter = new ConsoleLogWriter(config.LogLevel);
				proxy.ServerCertificate = config.ServerCertificate;

				Console.WriteLine("Starting TLS proxy...");

				proxy.Start();

				if (config.Forever)
				{
					Console.WriteLine("Proxy started.");
					Thread.Sleep(Timeout.Infinite);
				}
				else
				{
					Console.WriteLine("Press 'Enter' to stop the proxy.");

					Console.ReadLine();

					proxy.Stop();
				}
			}
		}

		private static void ShowHelp(string errors)
		{
			string applicationName = AppDomain.CurrentDomain.FriendlyName;
			Console.WriteLine("=====================================================================");
			Console.WriteLine(" {0} ", applicationName);
			Console.WriteLine("=====================================================================");
			Console.WriteLine();
			Console.WriteLine("Rebex Tiny TLS proxy.");
			Console.WriteLine();
			Console.WriteLine("The is a lightweight TLS proxy suitable for legacy operating systems.");
			Console.WriteLine("For more information, see https://github.com/rebexnet/RebexTinyTlsProxy");
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("Syntax: {0} CONNECTION_BINDING [OPTIONS]", applicationName);
			Console.WriteLine();
			Console.WriteLine("Syntax of CONNECTION_BINDING: CONNECTION_TYPE TLS_PROTOCOLS PORT_BINDING");
			Console.WriteLine();
			Console.WriteLine("Example: -fromTLS TLS10-TLS13 4443:httpbin.org:80 -c cert.pfx#password");
			Console.WriteLine("Example: -toTLS   TLS10-TLS13 8080:httpbin.org:443");
			Console.WriteLine("Example: -noTLS   -           8080:httpbin.org:80");
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("'CONNECTION_TYPE' defines inbound and outbound protocols:");
			Console.WriteLine(" -fromTLS        TLS   -> Plain");
			Console.WriteLine(" -noTLS          Plain -> Plain");
			Console.WriteLine(" -toTLS          Plain -> TLS");
			Console.WriteLine(" -toSMTP         Plain -> SMTP with explicit TLS");
			Console.WriteLine();
			Console.WriteLine("'TLS_PROTOCOLS' defines enabled TLS versions.");
			Console.WriteLine("Available values: TLS10, TLS11, TLS12, TLS13");
			Console.WriteLine("                 You can specify exact range like TLS12-TLS13");
			Console.WriteLine("                 You can specify min version like TLS11-");
			Console.WriteLine("                 You can specify max version like -TLS12");
			Console.WriteLine();
			Console.WriteLine("'PORT_BINDING' defines port forwarding rule.");
			Console.WriteLine("Syntax is LOCAL_PORT:HOST_NAME:HOST_PORT");
			Console.WriteLine(" LOCAL_PORT      Proxy local port to listen for inbound connections");
			Console.WriteLine(" HOST_NAME       Hostname or IP address the proxy connects to");
			Console.WriteLine(" HOST_PORT       Remote port the proxy connects to");
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("Available OPTIONS:");
			Console.WriteLine(" -c path#pass    Certificate path and password (separated by #)");
			Console.WriteLine(" -h              Show this help");
			Console.WriteLine(" -v              Verbose logging ON");
			Console.WriteLine(" -d              Debug logging ON");
			Console.WriteLine(" -I              Info logging OFF");
			Console.WriteLine(" -t timeout      Proxy Timeout in seconds (default is 60 seconds)");
			Console.WriteLine(" -forever        Run forever");
			Console.WriteLine();

			if (!string.IsNullOrEmpty(errors))
			{
				Console.WriteLine();
				Console.WriteLine(errors);
			}
		}
	}
}
