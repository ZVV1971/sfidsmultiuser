using CommandLine;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using PS_Ids_Async;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;

namespace testconsole
{
    class Program
    {
        private static readonly string memMappedFileName = @"C:\Users\Uladzimir_Zakharenka\source\repos\ZVV1971\sfidsmultiuser\sfids.csv";
        private static string pathToKeePassDb = @"C:\Users\Uladzimir_Zakharenka\source\repos\ZVV1971\sfidsmultiuser\LINX_GERMANY.kdbx";
        private static string groupName = "EPAM";
        private static string entryName = "EPAM";
        private static string domainName;
        private static HttpClient client = new HttpClient();

        static async Task Main(string[] args)
        {

            var result = Parser.Default.ParseArguments<Options>(args)
                .MapResult(
                (Options opt) => {
                    domainName = opt.SalesForceDomain;
                    groupName = opt.GroupName;
                    entryName = opt.EntryName;
                    pathToKeePassDb = opt.KDBXPath;
                    return 1;
                }, 
                (IEnumerable<Error> errs) => 
                {
                    Console.WriteLine("Press any key to exit...");
                    Console.ReadKey();
                    Environment.Exit(-1);
                    return 0;
                });

            //domainName = result.
            SecureString securePwd = new SecureString();
            ConsoleKeyInfo key;

            Console.Write("Enter password for KeePass: ");
            do
            {
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace)
                {
                    // Append the character to the password.
                    if (key.Key != ConsoleKey.Enter) securePwd.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
                else
                {
                    if (securePwd.Length > 0) securePwd.RemoveAt(securePwd.Length - 1);
                }
                // Exit if Enter key is pressed.
            } while (key.Key != ConsoleKey.Enter);

            Dictionary<string, ProtectedString> dic = OpenKeePassDB(securePwd);
            Dictionary<string,string> salesForceSID = await GetSalesForceSessionId(dic);
            if (salesForceSID.Count == 0)
            {
                Console.WriteLine("Error getting SalesForce session ID. Exiting...");
                Console.ReadKey();
                return;
            }

            Task[] tasks = new Task[2];
            tasks[0] = Task.Factory.StartNew(()=>dowork(memMappedFileName, "1"));
            tasks[1] = Task.Factory.StartNew(()=>dowork(memMappedFileName, "2"));
            Task.WaitAll(tasks);
            Console.WriteLine("All threads complete");
            Console.ReadKey();
        }

        static void dowork(string FileToOpen, string Id)
        {
            PS_Ids_Async.PowerShellId psid = PowerShellId.Create(FileToOpen);
            string c;
            do
            {
                c = psid.GetCurrentID();
                if (!c.Equals(string.Empty))
                {
                    Console.WriteLine($"Input from {Id} value {c}");
                    continue;
                }
                break;
            } while (true);
        }
    
        static Dictionary<string, ProtectedString> OpenKeePassDB (SecureString Password)
        {
            PwDatabase PwDB = new PwDatabase();
            IOConnectionInfo mioInfo = new IOConnectionInfo();
            mioInfo.Path = pathToKeePassDb;
            CompositeKey compositeKey = new CompositeKey();
            compositeKey.AddUserKey(new KcpPassword(Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(Password))));
            IStatusLogger statusLogger = new NullStatusLogger();

            Dictionary<string, ProtectedString> dict = new Dictionary<string, ProtectedString>();

            try
            {
                PwDB.Open(mioInfo, compositeKey, statusLogger);
                PwObjectList<PwGroup> groups = PwDB.RootGroup.GetGroups(true);
                
                foreach(PwGroup grp in groups)
                {
                    if (grp.Name.Equals(groupName))
                    {
                        PwObjectList<PwEntry> entries = grp.GetEntries(false);
                        foreach (PwEntry ent in entries)
                        {
                            if (ent.Strings.ReadSafe("Title").Equals(entryName))
                            {
                                dict.Add("Salt", new ProtectedString(true, ent.Strings.ReadSafe("Salt")));
                                dict.Add("Password", new ProtectedString(true, ent.Strings.ReadSafe("Password")));
                                dict.Add("AESPass", new ProtectedString(true, ent.Strings.ReadSafe("AESpassword")));
                                dict.Add("UserName", new ProtectedString(true, ent.Strings.ReadSafe("UserName")));
                                dict.Add("IV", new ProtectedString(true, ent.Strings.ReadSafe("IV")));
                                dict.Add("SecurityToken", new ProtectedString(true, ent.Strings.ReadSafe("SecurityToken")));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to open KeePassDb \n{ex.Message}");
            }
            finally
            {
                PwDB.Close();
            }

            return dict;
        }
    
        static async Task<Dictionary<string, string>> GetSalesForceSessionId(Dictionary<string, ProtectedString> creds)
        {
            string xmlString = @"<?xml version=""1.0"" encoding=""utf-8""?>
                  <env:Envelope xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
                              xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
                              xmlns:env=""http://schemas.xmlsoap.org/soap/envelope/"">
                     <env:Body>
                      <n1:login xmlns:n1=""urn:partner.soap.sforce.com"">
                           <n1:username>uz@epam.com</n1:username>
                                <n1:password>pwd</n1:password>
                                 </n1:login>
                                  </env:Body>
                               </env:Envelope>
                ";
            XmlDocument x = new XmlDocument();
            x.LoadXml(xmlString);
            //Root.Envelope.Body.login
            foreach ( XmlElement n in x.ChildNodes[1].ChildNodes[0].ChildNodes[0].ChildNodes) 
            {
                switch (n.LocalName)
                {
                    case "username":
                        n.FirstChild.InnerText = creds["UserName"].ReadString();
                        break;
                    case "password":
                        n.FirstChild.InnerText = creds["Password"].ReadString() + creds["SecurityToken"].ReadString();
                        break;
                }
            }

            var httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("https://" + domainName + ".salesforce.com/services/Soap/u/45.0"),
                Headers = {
                    { HttpRequestHeader.Accept.ToString(), "application/json" },
                    { "SOAPAction", "login" }
                },
                Content = new StringContent(x.OuterXml, Encoding.UTF8, "text/xml")
            };

            try
            {
                HttpResponseMessage msg = await client.SendAsync(httpRequestMessage);
                if (msg.IsSuccessStatusCode) 
                { 
                    x.LoadXml(msg.Content.ReadAsStringAsync().Result); 
                }
                else return new Dictionary<string, string>();
            }
            catch
            {
                return new Dictionary<string, string>();
            }

            Dictionary<string, string>  dict = new Dictionary<string, string>();

            foreach (XmlElement n in x.ChildNodes[1].ChildNodes[0].ChildNodes[0].ChildNodes[0].ChildNodes)
            {
                switch (n.LocalName)
                {
                    case "serverUrl":
                        dict.Add("serverUrl",
                            //substitute Soap/u with data/v45
                            Regex.Replace(n.FirstChild.InnerText.Substring(0, n.FirstChild.InnerText.LastIndexOf('/')), @"(Soap/u/)([\d\.]+)", "data/v$2"));
                        break;
                    case "sessionId":
                        dict.Add("sessionId",n.FirstChild.InnerText);
                        break;
                }
            }
            return dict;
        }
    }

    class Options
    //https://github.com/gsscoder/commandline/wiki/Latest-Version
    {
        [Option('d', "salesforcedomain",
            Default = "test", 
            HelpText = "Represents a domain used to log into SalesForce from, e.g. https://test.salesforce.com", 
            MetaValue ="test")]
        public string SalesForceDomain { get; set; }

        [Option('g', "groupname", Required =true
            ,HelpText ="Name of the group in the KeePass file where to look for the entry")]
        public string GroupName { get; set; }

        [Option('e', "entryname", Required = true,
            HelpText ="Name of the Entry within the group in the KeePass file with necessary credentials")]
        public string EntryName { get; set; }

        [Option('k', "kdbxpath", Required = true,
            HelpText ="Path to the KeePass file with the credentials. The file must not be key-file protected!")]
        public string KDBXPath { get; set; }

        public string GetUsage() { return ""; }
    }
}