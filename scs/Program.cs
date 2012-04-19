using System;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Security;
using System.Security.Cryptography;
using System.Diagnostics;

namespace scs
{
    class Program
    {
        static TcpListener listener;
        static TcpClient client;
        static NetworkStream stream;

        static RSACryptoServiceProvider myRSAKey;
        static RSACryptoServiceProvider thereRSAKey;
        static Aes aes;

        static bool connected = false;
        static bool prompting = true;
        
        static void Main(string[] args)
        {
            if (args.Length == 0) { Console.WriteLine("Syntax:\n  scs <host> <port>\n  scs <port>"); return; }

            int port = 0;            
            int part = 0;    
            
            if (args.Length == 2) { part = 1; }
            if (args.Length > 0) 
            {
                try { port = Convert.ToInt32(args[part]); }
                catch { Console.WriteLine("Invalid Port."); return; }
            }

            myRSAKey = new RSACryptoServiceProvider(512);
            thereRSAKey = new RSACryptoServiceProvider(512);
            aes = Aes.Create();

            if (args.Length == 1) { Listen(port); }
            else if (args.Length == 2) { Connect(args[0], port); }

            while (prompting)
            {
                Console.Write("");
                string input = Console.ReadLine();
                if (input.ToLower() == "exit") { if (connected) { stream.Close(); } prompting = false; connected = false; }
                if (connected) { Write(input); }
            }
        }
    
        static void Listen(int port)
        {
            listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine("Listening...");
            client = listener.AcceptTcpClient();
            stream = client.GetStream();
            listener.Stop();
            connected = true;
            Console.WriteLine("Connected.");
            ReceiveKey();
            Read(new byte[0]);
        }
        static void Connect(string host, int port)
        {
            client = new TcpClient();
            Console.WriteLine("Connecting...");
            try
            {
                client.Connect(host, port);
                stream = client.GetStream();
                connected = true;
            }
            catch 
            {
                Console.WriteLine("Connect Failed.");
            }
            if (connected)
            {
                Console.WriteLine("Connected.");
                SendKey();
                Read(new byte[0]);
            }
        }

        static void Read(byte[] data)
        {
            if (connected)
            {
                byte[] readBuffer = new byte[1024];

                Task<int> reader = Task<int>.Factory.FromAsync(stream.BeginRead, stream.EndRead, readBuffer, 0, readBuffer.Length, null);
                reader.ContinueWith(ant =>
                {
                    int readSize = ant.Result;
                    if (readSize > 0)
                    {
                        byte[] end = new byte[4];
                        Buffer.BlockCopy(readBuffer, readSize - 4, end, 0, 4);
                        if (end[0] == 0 && end[1] == 0 && end[2] == 0 && end[3] == 0)
                        {
                            byte[] cryptodata = new byte[data.Length + (readSize - 4)];
                            Buffer.BlockCopy(data, 0, cryptodata, 0, data.Length);
                            Buffer.BlockCopy(readBuffer, 0, cryptodata, data.Length, readSize - 4);
                            string output = Decrypt(cryptodata);
                            Console.WriteLine(output);
                            Read(new byte[0]);
                        }
                        else
                        {                            
                            if (data.Length + readBuffer.Length > short.MaxValue ) { Console.WriteLine("Flood attempt detected."); Cleanup(); return; }
                            else 
                            {
                                byte[] whole = new byte[data.Length + readBuffer.Length];
                                Buffer.BlockCopy(data, 0, whole, 0, data.Length);
                                Buffer.BlockCopy(readBuffer, 0, whole, data.Length, readSize);
                                Read(whole);
                            }
                        }
                    }
                    else
                    {
                        Cleanup();
                    }
                }, TaskContinuationOptions.OnlyOnRanToCompletion);
                reader.ContinueWith(ant =>
                {
                    Cleanup();
                }, TaskContinuationOptions.OnlyOnFaulted);
            }
        }
        static void Write(string data)
        {
            if (connected)
            {
                byte[] input = Encrypt(data);

                Task writer = Task.Factory.FromAsync(stream.BeginWrite, stream.EndWrite, input, 0, input.Length, null, TaskCreationOptions.None);
                writer.ContinueWith(ant =>
                {
                    Cleanup();
                }, TaskContinuationOptions.OnlyOnFaulted);
            }
        }

        static byte[] Encrypt(string data)
        {
            byte[] encrypted = null;
            if (data == null || data.Length <= 0) { return encrypted; }
            using (Aes algorythm = Aes.Create())
            {
                algorythm.Key = aes.Key;
                algorythm.IV = aes.IV;

                ICryptoTransform encryptor = algorythm.CreateEncryptor(algorythm.Key, algorythm.IV);

                using (MemoryStream memory = new MemoryStream())
                {
                    using (CryptoStream crypto = new CryptoStream(memory, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter output = new StreamWriter(crypto))
                        {
                            output.Write(data);
                        }
                        byte[] final = memory.ToArray();
                        encrypted = new byte[final.Length + 4];
                        Buffer.BlockCopy(final, 0, encrypted, 0, final.Length);
                        encrypted[encrypted.Length - 4] = 0;
                        encrypted[encrypted.Length - 3] = 0;
                        encrypted[encrypted.Length - 2] = 0;
                        encrypted[encrypted.Length -1] = 0;
                    }
                }
            }
            return encrypted;
        }
        static string Decrypt(byte[] data)
        {
            string decrypted = null;
            using (Aes algorythm = Aes.Create())
            {
                algorythm.Key = aes.Key;
                algorythm.IV = aes.IV;

                ICryptoTransform decryptor = algorythm.CreateDecryptor(algorythm.Key, algorythm.IV);

                using (MemoryStream memory = new MemoryStream(data))
                {
                    using (CryptoStream crypto = new CryptoStream(memory, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader input = new StreamReader(crypto))
                        {
                            decrypted = input.ReadToEnd();
                        }
                    }
                }
            }
            return decrypted;
        }

        static void SendKey()
        {
            try
            {
                byte[] keyBuffer = UTF8Encoding.UTF8.GetBytes(myRSAKey.ToXmlString(false));
                stream.Write(keyBuffer, 0, keyBuffer.Length);

                keyBuffer = new byte[159];
                stream.Read(keyBuffer, 0, keyBuffer.Length);
                string xmlKey = UTF8Encoding.UTF8.GetString(keyBuffer);
                thereRSAKey.FromXmlString(xmlKey);

                byte[] encryptedKey = thereRSAKey.Encrypt(aes.Key, false);
                byte[] encryptedIV = thereRSAKey.Encrypt(aes.IV, false);
                byte[] buffer = new byte[encryptedKey.Length + encryptedIV.Length];

                encryptedKey.CopyTo(buffer, 0);
                encryptedIV.CopyTo(buffer, 64);
                stream.Write(buffer, 0, buffer.Length);

                Console.WriteLine("Keys exchanged.");
            }
            catch
            {
                Console.WriteLine("Key exchange failed.");
                Cleanup();
            }
        }
        static void ReceiveKey()
        {
            try
            {
                byte[] keyBuffer = new byte[159];
                stream.Read(keyBuffer, 0, keyBuffer.Length);
                string xmlKey = UTF8Encoding.UTF8.GetString(keyBuffer);
                thereRSAKey.FromXmlString(xmlKey);

                keyBuffer = UTF8Encoding.UTF8.GetBytes(myRSAKey.ToXmlString(false));
                stream.Write(keyBuffer, 0, keyBuffer.Length);

                byte[] buffer = new byte[128];
                stream.Read(buffer, 0, buffer.Length);

                byte[] encryptedKey = new byte[64];
                byte[] encryptedIV = new byte[64];
                Buffer.BlockCopy(buffer, 0, encryptedKey, 0, 64);
                Buffer.BlockCopy(buffer, 64, encryptedIV, 0, 64);

                byte[] key = myRSAKey.Decrypt(encryptedKey, false);
                byte[] iv = myRSAKey.Decrypt(encryptedIV, false);
                aes.Key = key;
                aes.IV = iv;

                Console.WriteLine("Keys exchanged.");
            }
            catch
            {
                Console.WriteLine("Key exchange failed.");
                Cleanup();
            }
        }

        static void Cleanup()
        {
            connected = false;
            prompting = false;
            if (stream != null) { stream.Close(); }
            if (client != null) { client.Close(); }
            Console.WriteLine("Disconnected.");
        }
    }
}
