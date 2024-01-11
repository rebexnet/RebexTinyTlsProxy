﻿using System;
using System.Threading;
using Rebex.Security.Certificates;
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

			// parse the arguments
			var config = new Arguments(args);

			// display errors and exit
			if (config.Errors.Length > 0)
			{
				ShowHelp();
				ShowErrors(config.Errors.ToString());
				return;
			}

			// display help if requested
			if (config.ShowHelp)
			{
				ShowHelp();
			}

			// register NIST and Brainpool curves
			AsymmetricKeyAlgorithm.Register(EllipticCurveAlgorithm.Create);

			// register Curve25519
			AsymmetricKeyAlgorithm.Register(Curve25519.Create);

			// initialize logger
			var logger = new ConsoleLogWriter(config.LogLevel);

			// set custom certificate validator
			if (config.CustomCertificateValidator)
			{
				CertificateEngine.SetCurrentEngine(new EnhancedCertificateEngine() { LogWriter = logger });
			}

			// initialize proxy
			using (var proxy = new TlsProxy(config.Bindings))
			{
				proxy.LogWriter = logger; // assign logger
				proxy.Timeout = config.Timeout * 1000; // set timeout in milliseconds
				proxy.ServerCertificate = config.ServerCertificate; // assign server certificate

				Console.WriteLine("Starting TLS proxy...");

				proxy.Start(); // start the proxy

				if (config.Forever)
				{
					Console.WriteLine("Proxy started.");

					Thread.Sleep(Timeout.Infinite); // wait infinitely
				}
				else
				{
					Console.WriteLine("Press 'Enter' to stop the proxy.");

					Console.ReadLine(); // wait for Enter

					Console.WriteLine("Stopping TLS proxy...");

					proxy.Stop(); // stop the proxy
				}
			}
		}

		private static void ShowHelp()
		{
			var applicationName = AppDomain.CurrentDomain.FriendlyName;
			var version = typeof(Program).Assembly.GetName().Version;
			Console.WriteLine("=====================================================================");
			Console.WriteLine(" {0} v{1}", applicationName, version);
			Console.WriteLine("=====================================================================");
			Console.WriteLine();
			Console.WriteLine("Rebex Tiny TLS proxy,");
			Console.WriteLine();
			Console.WriteLine("is a lightweight TLS proxy suitable for legacy operating systems.");
			Console.WriteLine("For more information, see https://github.com/rebexnet/RebexTinyTlsProxy");
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("Syntax: {0} CONNECTION_BINDING [OPTIONS]", applicationName);
			Console.WriteLine();
			Console.WriteLine("Examples:");
			Console.WriteLine(" {0} -fromTLS TLS10-TLS13 4443:httpbin.org:80 -c cert.pfx#password", applicationName);
			Console.WriteLine(" {0} -toTLS   TLS10-TLS13 8080:httpbin.org:443", applicationName);
			Console.WriteLine(" {0} -noTLS   -           8080:httpbin.org:80", applicationName);
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("Syntax of CONNECTION_BINDING: CONNECTION_TYPE TLS_PROTOCOLS PORT_BINDING");
			Console.WriteLine();
			Console.WriteLine("'CONNECTION_TYPE' defines inbound and outbound protocols:");
			Console.WriteLine(" -fromTLS        TLS   -> Plain");
			Console.WriteLine(" -noTLS          Plain -> Plain");
			Console.WriteLine(" -toTLS          Plain -> TLS");
			Console.WriteLine(" -toSMTP         Plain -> SMTP with explicit TLS");
			Console.WriteLine();
			Console.WriteLine("'TLS_PROTOCOLS' defines range of enabled TLS versions.");
			Console.WriteLine("Available values: TLS10, TLS11, TLS12, TLS13");
			Console.WriteLine("                 Specify exact range like TLS12-TLS13");
			Console.WriteLine("                 Specify min version like TLS11-");
			Console.WriteLine("                 Specify max version like -TLS12");
			Console.WriteLine();
			Console.WriteLine("'PORT_BINDING' defines port forwarding rule.");
			Console.WriteLine("Syntax is LOCAL_PORT:HOST_NAME:HOST_PORT");
			Console.WriteLine(" LOCAL_PORT      Proxy local port to listen for inbound connections");
			Console.WriteLine(" HOST_NAME       Hostname or IP address the proxy connects to");
			Console.WriteLine(" HOST_PORT       Remote port the proxy connects to");
			Console.WriteLine();
			Console.WriteLine();
			Console.WriteLine("Available OPTIONS:");
			Console.WriteLine(" -h              Show this help");
			Console.WriteLine(" -c path#pass    Certificate path and password (separated by #)");
			Console.WriteLine(" -t timeout      Proxy Timeout in seconds (default is 60 seconds)");
			Console.WriteLine(" -validator      Use custom certificate validator");
			Console.WriteLine(" -forever        Run forever");
			Console.WriteLine(" -v              Verbose logging ON");
			Console.WriteLine(" -d              Debug logging ON");
			Console.WriteLine(" -I              Info logging OFF");
			Console.WriteLine();
		}

		private static void ShowErrors(string errors)
		{
			if (string.IsNullOrEmpty(errors))
				return;

			var fc = Console.ForegroundColor;
			Console.ForegroundColor = ConsoleColor.Red;
			Console.WriteLine();
			Console.WriteLine("Cannot start due to error:");
			Console.WriteLine(errors);
			Console.ForegroundColor = fc;
		}
	}
}
