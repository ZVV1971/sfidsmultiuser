using CommandLine;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using Newtonsoft.Json.Linq;
using PS_Ids_Async;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;

namespace testconsole
{
    class Program
    {
        private static string pathToKeePassDb;//= @"C:\Users\Uladzimir_Zakharenka\source\repos\ZVV1971\sfidsmultiuser\LINX_GERMANY.kdbx";
        private static string groupName;
        private static string entryName;
        private static string domainName;
        private static string objectWithAttachments;
        private static int numberOfTHreads = 4;
        private static HttpClient client = new HttpClient();
        private static ConsoleKeyInfo key;
        private static ICryptoTransform encryptor;
        private static object locker = new object();
        private static string resultFileName;

        static async Task Main(string[] args)
        {

            var result = Parser.Default.ParseArguments<Options>(args)
                .MapResult(
                (Options opt) =>
                {
                    domainName = opt.SalesForceDomain;
                    groupName = opt.GroupName;
                    entryName = opt.EntryName;
                    pathToKeePassDb = opt.KDBXPath;
                    objectWithAttachments = Enum.GetName(typeof(SFObjectsWithAttachments), opt.SFObject);
                    resultFileName = opt.ecryptedAttachmentsTargetFile == null ?
                        "encrypted_"+objectWithAttachments + ".dat" : opt.ecryptedAttachmentsTargetFile;

                    return 1;
                },
                (IEnumerable<Error> errs) =>
                {
                    Console.WriteLine("Wait for 5 seconds or press any key to exit...");
                    Task.Factory.StartNew(() => Console.ReadKey()).Wait(TimeSpan.FromSeconds(5.0));
                    Environment.Exit(-1);
                    return 0;
                });

            SecureString securePwd = new SecureString();

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
            Console.WriteLine();

            Dictionary<string, ProtectedString> credentialsDict = new Dictionary<string, ProtectedString>(OpenKeePassDB(securePwd));
            Console.WriteLine($"Got {credentialsDict.Count} credentials");
            if (credentialsDict.Where(t => t.Key == "IV" || t.Key == "AESPass" || t.Key == "Salt").Count() < 3)
            {
                Console.WriteLine("Necessary cryptographic input is absent in the provided entry in the KDBX. Exiting...");
                Task.Factory.StartNew(() => Console.ReadKey()).Wait(TimeSpan.FromSeconds(5.0));
                return;
            }

            Dictionary<string, string> salesForceSID = new Dictionary<string, string>(await GetSalesForceSessionId(credentialsDict));
            if (salesForceSID.Count == 0)
            {
                Console.WriteLine("Error getting SalesForce session ID. Exiting...");
                Task.Factory.StartNew(() => Console.ReadKey()).Wait(TimeSpan.FromSeconds(5.0));
                return;
            }

            List<string> listOfIds = (await GetListOfIds(salesForceSID, objectWithAttachments)).ToList();
            if (listOfIds.Count != 0)
            {
                Console.WriteLine($"Got {listOfIds.Count} Ids in the {objectWithAttachments} object");
            }
            else
            {
                Console.WriteLine("Nothing to extract. Exiting...");
                Task.Factory.StartNew(() => Console.ReadKey()).Wait(TimeSpan.FromSeconds(5.0));
                return;
            }

            #region CryptographicStuff
            SymmetricAlgorithm cipher = SymmetricAlgorithm.Create("AesManaged");
            cipher.Mode = CipherMode.CBC;
            cipher.Padding = PaddingMode.PKCS7;
            cipher.IV = Convert.FromBase64String(credentialsDict["IV"].ReadString());
            Byte[] passwordKey = NewPasswordKey(SecureStringExten.ToSecureString(credentialsDict["AESPass"].ReadString()), 
                credentialsDict["Salt"].ReadString());
            encryptor = cipher.CreateEncryptor(passwordKey, cipher.IV);
            #endregion

            List<Task> tasks = new List<Task>();
            using (StreamWriter resultStream = new StreamWriter(resultFileName, false, Encoding.ASCII))
            {
                for (int i = 0; i < numberOfTHreads; i++)
                {
                    tasks.Add(Task.Run(
                        () => doWork(i.ToString(), listOfIds.ToList(), salesForceSID, objectWithAttachments, encryptor, resultStream)));
                }
                Task.WaitAll(tasks.ToArray());
            }
            Console.WriteLine("All threads complete");
            Task.Factory.StartNew(() => Console.ReadKey()).Wait(TimeSpan.FromSeconds(5.0));
        }

        static Byte[] NewPasswordKey(SecureString password, string salt)
        {
            int iterations = 1000;
            int keySize = 256;
            Rfc2898DeriveBytes PasswordDeriveBytes = new Rfc2898DeriveBytes(Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(password)),
                Encoding.ASCII.GetBytes(salt), iterations, HashAlgorithmName.SHA256);
            return PasswordDeriveBytes.GetBytes(keySize / 8);
        }
        static async Task<IEnumerable<string>> GetListOfIds(IDictionary<string, string> dic, string obj)
        {
            HttpResponseMessage listOfIds = new HttpResponseMessage();
            List<string> lst = new List<string>();
            
            Uri requestUri = new Uri(dic["serverUrl"] + "/query/?q=SELECT+Id+FROM+" + obj);
            
            while (true)
            {

                listOfIds = await ReadFromSalesForce(requestUri, dic);
                
                if (listOfIds.StatusCode != HttpStatusCode.OK) break;

                var j = JObject.Parse(await listOfIds.Content.ReadAsStringAsync());
                foreach (var v in j["records"])
                {
                    lst.Add(v["Id"].ToString());
                }

                if (j["nextRecordsUrl"] != null)
                {
                    requestUri = new Uri(j["nextRecordsUrl"].ToString());
                }
                else break;
            }
            return lst;
        }

        static async Task doWork(string Id, ICollection<string> listOfIds, IDictionary<string,string> creds, string obj, ICryptoTransform cryptoTrans, TextWriter writer)
        {
            PowerShellId psid = new PowerShellId();
            int currentId;
            Guid guid = Guid.NewGuid();
            do
            {
                currentId = psid.GetCurrentID();
                if (currentId < listOfIds.Count && !(listOfIds.ToList())[currentId].Equals(string.Empty))
                {
                    HttpResponseMessage resp = await ReadFromSalesForce(
                        new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + (listOfIds.ToList())[currentId] + "/Body")
                        , creds);
                    if (resp != null && resp.StatusCode == HttpStatusCode.OK)
                    {
                        Console.WriteLine(
                              $"Input #{currentId} with ID:{(listOfIds.ToList())[currentId]} has resulted in {resp.Content.ReadAsStreamAsync().Result.Length} bytes read by a thread #{guid}");
                        using (MemoryStream stream = new MemoryStream())
                        {
                            using (CryptoStream cstream = new CryptoStream(stream, cryptoTrans, CryptoStreamMode.Write))
                            {
                                cstream.Write(resp.Content.ReadAsByteArrayAsync().Result, 0, Convert.ToInt32(resp.Content.ReadAsStreamAsync().Result.Length));
                                cstream.FlushFinalBlock();
                                byte[] encrypted = stream.ToArray();
                                lock (locker)
                                {
                                    writer.WriteLine(listOfIds.ToList()[currentId] + "," + Convert.ToBase64String(encrypted));
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"{(listOfIds.ToList())[currentId]} failed to read. Sending to the queue again");
                        listOfIds.Append((listOfIds.ToList())[currentId]);
                    }
                    continue;
                }
                break;
            } while (true);
        }
    
        static IDictionary<string, ProtectedString> OpenKeePassDB (SecureString Password)
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
            //Delete key-value pairs where values are empty
            dict.Where(d=>d.Value.IsEmpty).ToList().ForEach(t=>dict.Remove(t.Key));
            return dict;
        }
    
        static async Task<IDictionary<string, string>> GetSalesForceSessionId(IDictionary<string, ProtectedString> creds)
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
                Console.WriteLine("Sending a request to SF for log-in...");
                HttpResponseMessage msg = await client.SendAsync(httpRequestMessage,HttpCompletionOption.ResponseHeadersRead);
                if (msg.IsSuccessStatusCode)
                {
                    Console.WriteLine("Got successful login response");
                    x.LoadXml(msg.Content.ReadAsStringAsync().Result);
                }
                else
                {
                    Console.WriteLine("SalesForce login failed");
                    return new Dictionary<string, string>();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
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
                            Regex.Replace(n.FirstChild.InnerText.Substring(0, n.FirstChild.InnerText.LastIndexOf('/')), 
                            @"(Soap/u/)([\d\.]+)", "data/v$2"));
                        break;
                    case "sessionId":
                        dict.Add("sessionId",n.FirstChild.InnerText);
                        break;
                }
            }
            return dict;
        }

        static async Task<HttpResponseMessage> ReadFromSalesForce(Uri requestUri, IDictionary<string,string> dic)
        {
            HttpResponseMessage response = new HttpResponseMessage();
            List<string> lst = new List<string>();
            HttpRequestMessage msg = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = requestUri,
                Headers = {
                    { HttpRequestHeader.Accept.ToString(), "application/json" },
                    { "Authorization", "Bearer " + dic["sessionId"] }
                            }
            };

            try
            {
                response = await client.SendAsync(msg);
            }
            catch
            {}
            return response;
        }
    }

    class Options
    //https://github.com/gsscoder/commandline/wiki/Latest-Version
    {
        [Option('d', "salesforcedomain",
            Default = "test",
            HelpText = "Represents a domain used to log into SalesForce from, e.g. https://test.salesforce.com",
            MetaValue = "test")]
        public string SalesForceDomain { get; set; }

        [Option('g', "groupname", Required = true,
            HelpText = "Name of the group in the KeePass file where to look for the entry")]
        public string GroupName { get; set; }

        [Option('e', "entryname", Required = true,
            HelpText = "Name of the Entry within the group in the KeePass file with necessary credentials")]
        public string EntryName { get; set; }

        [Option('k', "kdbxpath", Required = true,
            HelpText = "Path to the KeePass file with the credentials. The file must not be key-file protected!")]
        public string KDBXPath { get; set; }

        [Option('o', "sfobject", Default = SFObjectsWithAttachments.Document,
            HelpText ="Points out which SalesForce object the body of attachments should be taken from")]
        public SFObjectsWithAttachments SFObject { get; set; }

        [Option('t',"targetfile", //Default = "encrypted_Attachments.dat",
            HelpText ="Set path to the target file to store encrypted attachments to")]
        public string ecryptedAttachmentsTargetFile { get; set; }
    }

    enum SFObjectsWithAttachments
    {
        Attachment,
        Document
    }
}