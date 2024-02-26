using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Rebex.Net;

namespace Rebex.Proxy
{
	/// <summary>
	/// Common API for data sender/receiver.
	/// </summary>
	public interface IDataProvider
	{
		byte[] Buffer { get; }
		EndPoint LocalEndpoint { get; }
		EndPoint RemoteEndpoint { get; }
		IAsyncResult BeginReceive(AsyncCallback callback);
		int EndReceive(IAsyncResult ar);
		void Send(byte[] buffer, int offset, int count);
		void Shutdown();
		void Close();
	}

	/// <summary>
	/// TLS-based data provider.
	/// </summary>
	public class TlsSocketDataProvider : IDataProvider
	{
		readonly TlsSocket _socket;

		public byte[] Buffer { get; private set; }

		public EndPoint LocalEndpoint { get { return _socket.LocalEndPoint; } }
		public EndPoint RemoteEndpoint { get { return _socket.RemoteEndPoint; } }

		public TlsSocketDataProvider(TlsSocket socket, int bufferSize)
		{
			_socket = socket;
			Buffer = new byte[bufferSize];
		}

		public IAsyncResult BeginReceive(AsyncCallback callback)
		{
			return _socket.BeginReceive(Buffer, 0, Buffer.Length, 0, callback, null);
		}

		public int EndReceive(IAsyncResult ar)
		{
			return _socket.EndReceive(ar);
		}

		public void Send(byte[] buffer, int offset, int count)
		{
			_socket.Send(buffer, offset, count, 0);
		}

		public void Shutdown()
		{
			_socket.Shutdown(SocketShutdown.Send);
		}

		public void Close()
		{
			_socket.Close();
		}
	}

	/// <summary>
	/// SMTP-aware data provider.
	/// </summary>
	public class SmtpExplicitDataProvider : IDataProvider
	{
		readonly TlsSocket _socket;

		readonly StringBuilder _builder;
		private Exception _error;
		private int _welcomeLength;

		public byte[] Buffer { get; private set; }

		public EndPoint LocalEndpoint { get { return _socket.LocalEndPoint; } }
		public EndPoint RemoteEndpoint { get { return _socket.RemoteEndPoint; } }

		public SmtpExplicitDataProvider(TlsSocket socket, int bufferSize)
		{
			_socket = socket;
			Buffer = new byte[bufferSize];
			_builder = new StringBuilder();
		}

		public IAsyncResult BeginReceive(AsyncCallback callback)
		{
			if (_socket.IsSecure)
				return _socket.BeginReceive(Buffer, 0, Buffer.Length, 0, callback, null);
			else
				return _socket.BeginReceive(Buffer, 0, Buffer.Length, 0, SecureExplicit(callback), null);
		}

		private AsyncCallback SecureExplicit(AsyncCallback userCallback)
		{
			AsyncCallback callback = null;
			callback = ar =>
			{
				try
				{
					int readCount = _socket.EndReceive(ar);
					if (readCount == 0)
						throw new InvalidOperationException("Not enough data.");

					string welcome = Encoding.ASCII.GetString(Buffer, 0, readCount);
					if (!welcome.EndsWith("\n"))
						welcome += ReceiveLine();

					if (!welcome.StartsWith("220 "))
						throw new InvalidOperationException(string.Format("Unexpected server response: {0}", welcome));

					SendCommand("EHLO Rebex-TLS-Proxy");

					while (true)
					{
						var line = ReceiveLine();
						if (line.StartsWith("250-"))
							continue;
						if (line.StartsWith("250 "))
							break;
						throw new InvalidOperationException(string.Format("Unexpected server response: {0}", line));
					}

					SendCommand("STARTTLS");

					{
						var line = ReceiveLine();
						if (!line.StartsWith("220 "))
							throw new InvalidOperationException(string.Format("Unexpected server response: {0}", line));

						_socket.Negotiate();
					}

					_welcomeLength = Encoding.ASCII.GetBytes(welcome, 0, welcome.Length, Buffer, 0);
				}
				catch (Exception ex)
				{
					_error = ex;
				}
				finally
				{
					userCallback(ar);
				}
			};
			return callback;
		}

		private string ReceiveLine()
		{
			while (true)
			{
				int n = _socket.Receive(Buffer, 0, Buffer.Length);
				if (n == 0)
					throw new InvalidOperationException("Not enough data.");
				_builder.Append(Encoding.ASCII.GetString(Buffer, 0, n));
				if (Buffer[n - 1] == '\n')
				{
					string response = _builder.ToString().TrimEnd();
					int lastLF = response.LastIndexOf('\n');
					if (lastLF >= 0)
						response = response.Substring(lastLF + 1);
					_builder.Length = 0;
					return response;
				}
			}
		}

		private int SendCommand(string command)
		{
			int n = Encoding.ASCII.GetBytes(command, 0, command.Length, Buffer, 0);
			Buffer[n++] = (byte)'\r';
			Buffer[n++] = (byte)'\n';
			return _socket.Send(Buffer, 0, n);
		}

		public int EndReceive(IAsyncResult ar)
		{
			if (_error != null)
				throw new TlsException("Unable to secure connection.", _error);
			if (_welcomeLength > 0)
				return Reset(ref _welcomeLength);
			return _socket.EndReceive(ar);
		}

		private static int Reset(ref int value)
		{
			var n = value;
			value = 0;
			return n;
		}

		public void Send(byte[] buffer, int offset, int count)
		{
			_socket.Send(buffer, offset, count, 0);
		}

		public void Shutdown()
		{
			_socket.Shutdown(SocketShutdown.Send);
		}

		public void Close()
		{
			_socket.Close();
		}
	}
}
