using System;
using System.Collections.Generic;
using System.Text;
using Rebex.Net;
using Rebex.Security.Certificates;

namespace Rebex.Proxy
{
	[Flags]
	public enum ProxyValidationOptions
	{
		None = 0,
		AcceptAll = 1,
		SkipRevCheck = 2,
		IgnoreTimeCheck = 4,
	}

	public interface IProxySettings
	{
		ProxyBinding[] Bindings { get; }
		int TimeoutMilliseconds { get; }
		CertificateChain ServerCertificate { get; }
		bool WeakCiphers { get; }
		bool InsecureCiphers { get; }
		ProxyValidationOptions ValidationOptions { get; }
	}

	/// <summary>
	/// Simple input argument parser.
	/// </summary>
	public class Arguments : IProxySettings
	{
		public ProxyBinding[] Bindings { get; private set; }

		public bool ShowHelp { get; private set; }

		public LogLevel LogLevel { get; private set; }

		public bool Forever { get; private set; }

		public int TimeoutMilliseconds { get; private set; }

		public bool CustomCertificateValidator { get; private set; }

		public bool WeakCiphers { get; private set; }

		public bool InsecureCiphers { get; private set; }

		public CertificateChain ServerCertificate { get; private set; }

		public ProxyValidationOptions ValidationOptions { get; private set; }

		public StringBuilder Errors { get; private set; }

		public Arguments(string[] args)
		{
			Errors = new StringBuilder();

			// defaults
			TimeoutMilliseconds = 60 * 1000;
			LogLevel = LogLevel.Info;

			bool certificateRequired = false;
			var bindings = new List<ProxyBinding>();
			try
			{
				for (int i = 0; i < args.Length; i++)
				{
					switch (args[i])
					{
						case "-h":
							ShowHelp = true;
							return;

						case "-v": // Verbose logging ON
							if (LogLevel > LogLevel.Verbose)
								LogLevel = LogLevel.Verbose;
							break;

						case "-d": // Debug logging ON
							if (LogLevel > LogLevel.Debug)
								LogLevel = LogLevel.Debug;
							break;

						case "-I": // Info logging OFF
							if (LogLevel == LogLevel.Info)
								LogLevel = LogLevel.Error;
							break;

						case "-fromTLS":
						case "-noTLS":
						case "-toTLS":
						case "-toSMTP":
						case "-TLStoTLS":
							var type = args[i];
							if (++i >= args.Length)
								break;
							var protocols = args[i];
							if (++i >= args.Length)
								break;
							var binding = GetBinding(type, protocols, args[i]);
							certificateRequired |= IsCertificateRequired(binding);
							bindings.Add(binding);
							break;

						case "-forever":
							Forever = true;
							break;

						case "-validator":
							CustomCertificateValidator = true;
							break;

						case "-weak":
							WeakCiphers = true;
							break;

						case "-insecure":
							InsecureCiphers = true;
							break;

						case "-vo":
							if (++i < args.Length)
							{
								string[] options = args[i].Split(',');
								foreach (var op in options)
								{
									ProxyValidationOptions option;
									if (Enum.TryParse(op, out option))
									{
										ValidationOptions |= option;
									}
									else
									{
										Errors.AppendLine(string.Format("Unknown validation option: {0}", op));
									}
								}
							}
							break;

						case "-c":
							if (++i < args.Length)
							{
								ServerCertificate = CertificateChain.BuildFrom(GetCertificate(args[i]));
							}
							break;

						case "-t":
							if (++i < args.Length)
							{
								TimeoutMilliseconds = GetTimeout(args[i]) * 1000;
							}
							break;

						default:
							Errors.AppendLine(string.Format("Unknown option: {0}", args[i]));
							break;
					}
				}
			}
			catch (ParserException ex)
			{
				Errors.AppendLine(ex.Message);
			}
			catch (Exception ex)
			{
				Errors.AppendLine(ex.ToString());
			}

			if (bindings.Count == 0)
			{
				Errors.AppendLine("No connection BINDING specified.");
			}

			if (certificateRequired && ServerCertificate == null)
			{
				Errors.AppendLine("Certificate option required for TLS on inbound tunnel.");
			}

			Bindings = bindings.ToArray();
		}

		private bool IsCertificateRequired(ProxyBinding binding)
		{
			return binding.InboundTlsVersions != TlsVersion.None;
		}

		private static ProxyBinding GetBinding(string bindingType, string protocols, string binding)
		{
			var versions = new TlsVersion[2];
			var protocolsArray = protocols.Split(':');
			if (protocolsArray.Length > versions.Length)
			{
				throw new ParserException("Invalid TLS_PROTOCOLS ({0}).", protocols);
			}
			for (int i = 0; i < protocolsArray.Length; i++)
			{
				var parts = protocolsArray[i].Split('-');
				if (parts.Length != 2)
				{
					throw new ParserException("Invalid TLS_PROTOCOLS ({0}).", protocols);
				}
				versions[i] = GetRange(GetTlsProtocol(parts[0], TlsVersion.TLS10), GetTlsProtocol(parts[1], TlsVersion.TLS13));
			}

			BindingType type;
			TlsVersion inVersions, outVersions;
			switch (bindingType)
			{
				case "-noTLS":
					type = BindingType.NoTLS; inVersions = TlsVersion.None; outVersions = TlsVersion.None; break;
				case "-toTLS":
					type = BindingType.ToTLS; inVersions = TlsVersion.None; outVersions = versions[0]; break;
				case "-toSMTP":
					type = BindingType.ToSMTP; inVersions = TlsVersion.None; outVersions = versions[0]; break;
				case "-fromTLS":
					type = BindingType.FromTLS; inVersions = versions[0]; outVersions = TlsVersion.None; break;
				case "-TLStoTLS":
					type = BindingType.TLStoTLS; inVersions = versions[0]; outVersions = versions[1]; break;
				default:
					throw new ArgumentException(string.Format("Invalid CONNECTION_TYPE ({0}).", bindingType));
			}

			if (type == BindingType.TLStoTLS)
			{
				if (protocolsArray.Length != 2)
					throw new ParserException("Invalid TLS_PROTOCOLS ({0}).", protocols);
			}
			else
			{
				if (protocolsArray.Length != 1)
					throw new ParserException("Invalid TLS_PROTOCOLS ({0}).", protocols);
			}

			var bindingArray = binding.Split(':');
			if (bindingArray.Length != 3)
			{
				throw new ParserException("Invalid PORT_BINDING ({0}).", binding);
			}

			return new ProxyBinding(type, GetPort(bindingArray[0]), bindingArray[1], GetPort(bindingArray[2]), inVersions, outVersions);
		}

		private static TlsVersion GetRange(TlsVersion min, TlsVersion max)
		{
			if (min > max)
				throw new ParserException("Invalid protocols ({0}-{1}).", min, max);
			TlsVersion range = 0;
			for (int i = (int)min; i <= (int)max; i *= 2)
			{
				range |= (TlsVersion)i;
			}
			return range;
		}

		private static TlsVersion GetTlsProtocol(string value, TlsVersion defaultValue)
		{
			switch (value)
			{
				case "": return defaultValue;
				case "TLS10": return TlsVersion.TLS10;
				case "TLS11": return TlsVersion.TLS11;
				case "TLS12": return TlsVersion.TLS12;
				case "TLS13": return TlsVersion.TLS13;
				default: throw new ParserException(string.Format("Invalid protocol ({0}).", value));
			}
		}

		private static Certificate GetCertificate(string certPathAndPwd)
		{
			string[] parts = certPathAndPwd.Split('#');
			switch (parts.Length)
			{
				case 1:
					return Certificate.LoadPfx(parts[0], "");
				case 2:
					return Certificate.LoadPfx(parts[0], parts[1]);
				case 3:
					return Certificate.LoadDerWithKey(parts[0], parts[1], parts[2]);
				default:
					throw new ArgumentException(string.Format("Invalid certificate cert_path_and_password value ('{0}').", certPathAndPwd));
			}
		}

		private static int GetPort(string value)
		{
			int port = GetNumber(value);
			if (port > 0 && port <= ushort.MaxValue)
				return port;
			throw new ParserException("Invalid port ({0}).", value);
		}

		private static int GetTimeout(string value)
		{
			int n = GetNumber(value);
			if (n > 0)
				return n;
			throw new ParserException("Timeout has to be greater than 0 (but was {0}).", value);
		}

		private static int GetNumber(string value)
		{
			int number;
			if (!int.TryParse(value, out number))
			{
				throw new ParserException("Not a number ({0}).", value);
			}
			return number;
		}

		private class ParserException : Exception
		{
			public ParserException(string message) : base(message)
			{
			}
			public ParserException(string format, params object[] args) : base(string.Format(format, args))
			{
			}
		}
	}
}
