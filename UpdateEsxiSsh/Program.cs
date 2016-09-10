using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace UpdateEsxiSsh
{
    /// <summary>
    ///     Program
    /// </summary>
    public class Program
    {
        private static string _password;

        /// <exception cref="IOException">An I/O error occurred. </exception>
        /// <exception cref="OutOfMemoryException">There is insufficient memory to allocate a buffer for the returned string. </exception>
        /// <exception cref="SocketException">
        ///     Socket connection to the SSH server or proxy server could not be established, or an
        ///     error occurred while resolving the hostname.
        /// </exception>
        /// <exception cref="SshConnectionException">SSH session could not be established.</exception>
        /// <exception cref="SshException">Invalid Operation - An existing channel was used to execute this command.</exception>
        /// <exception cref="SshAuthenticationException">Authentication of SSH session failed.</exception>
        /// <exception cref="ProxyException">Failed to establish proxy connection.</exception>
        public static void Main(string[] args)
        {
            Console.Write("Host: ");
            var host = Console.ReadLine();
            Console.Write("Username (root): ");
            var username = Console.ReadLine();
            Console.Write($"Password of '{username}': ");
            _password = null;
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }
                _password += key.KeyChar;
            }
            Console.WriteLine("*****");
            Console.WriteLine();
            var kauth = new KeyboardInteractiveAuthenticationMethod(username);
            var pauth = new PasswordAuthenticationMethod(username, _password);

            kauth.AuthenticationPrompt += HandleKeyEvent;

            var connectionInfo = new ConnectionInfo(host, 22, username, pauth, kauth);

            var sshClient = new SshClient(connectionInfo);
            sshClient.Connect();


            var checkFirewall = sshClient.RunCommand("esxcli network firewall ruleset list -r httpClient").Result;

            if (!checkFirewall.Contains("true"))
            {
                sshClient.RunCommand("esxcli network firewall ruleset set -e true -r httpClient");
            }

            Console.WriteLine("Fetching profile list...");
            var result =
                sshClient.RunCommand("esxcli software sources profile list -d https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml | grep -i \"ESXi-6\"")
                         .Result;
            var stringReader = new StringReader(result);
            var list = new List<string>();
            while (true)
            {
                var line = stringReader.ReadLine();
                if (line != null)
                {
                    list.Add(line);
                }
                else
                {
                    break;
                }
            }

            var latest = list.OrderByDescending(s => s).First(s => s.ToLower().Contains("esxi-6.0.0-20") && s.Contains("standard"));
            Console.WriteLine(latest);
            var profile = latest.Split(' ').FirstOrDefault();
            Console.WriteLine($"Updating ESXi to '{profile}'");

            Console.WriteLine(
                sshClient.RunCommand($"esxcli software profile update -d https://hostupdate.vmware.com/software/VUM/PRODUCTION/main/vmw-depot-index.xml -p {profile}").Result);

            sshClient.Disconnect();

            Console.WriteLine("Done.");
            Console.ReadLine();
        }

        private static void HandleKeyEvent(object sender, AuthenticationPromptEventArgs e)
        {
            foreach (var prompt in e.Prompts)
            {
                if (prompt.Request.IndexOf("Password:", StringComparison.CurrentCultureIgnoreCase) != -1)
                {
                    prompt.Response = _password;
                }
            }
        }
    }
}