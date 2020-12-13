using AsyncSalesForceAttachments;
using CommandLine;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace SalesForceAttachmentsBackupTools
{
    class AttachmentsBackup
    {
        #region fields
        private static string pathToKeePassDb;
        private static string groupName;
        private static string entryName;
        private static string domainName;
        private static string objectWithAttachments;
        private static string resultFileName;
        private static string pathToComparisonResults;
        private static int numberOfThreads;
        private static HttpClient client = new HttpClient();
        private static ConsoleKeyInfo key;
        private static WorkingModes workingMode;
        private static List<string> listOfIds = null;
        private static MinSizeQueue<KeyValuePair<string, string>> minSizeQueue;
        private static TimeSpan waittime = TimeSpan.FromSeconds(30);
        private static ConsoleTraceListener consoleTraceListener = new ConsoleTraceListener();
        #endregion fields
        [MTAThread]
        static async Task Main(string[] args)
        {
            int result = Parser.Default.ParseArguments<Options>(args)
                .MapResult(
                (Options opt) =>
                {
                    domainName = opt.SalesForceDomain;
                    groupName = opt.GroupName;
                    entryName = opt.EntryName;
                    pathToKeePassDb = opt.KDBXPath;
                    objectWithAttachments = Enum.GetName(typeof(SFObjectsWithAttachments), opt.SFObject);
                    resultFileName = opt.ecryptedAttachmentsTargetFile == null ?
                        "encrypted_" + objectWithAttachments + ".dat" : opt.ecryptedAttachmentsTargetFile;
                    workingMode = opt.WorkMode;
                    numberOfThreads = opt.numberOfWorkingThreads;
                    if (opt.logFilePath != null && !opt.logFilePath.Equals(String.Empty))
                    {
                        Trace.Listeners.Add(new TextWriterTraceListener(opt.logFilePath, "Backup_fileTracer"));
                        Trace.Listeners["Backup_fileTracer"].TraceOutputOptions |= TraceOptions.DateTime;
                    }
                    if (opt.logToConsole != 0) Trace.Listeners.Add(consoleTraceListener);
                    Trace.AutoFlush = true;
                    Trace.Listeners.Remove("Default");
                    if (workingMode == WorkingModes.Compare && 
                        (opt.comparisonResultsFilePath == null || opt.comparisonResultsFilePath.Equals(String.Empty))) 
                    {
                        Trace.TraceError($"If workmode is set to compare then comparison file must be provided.");
                        WaitExitingCountdown();
                        Environment.Exit(-1);
                        return 0;
                    }
                    else
                    {
                        pathToComparisonResults = opt.comparisonResultsFilePath;
                    }
                    Trace.TraceInformation("Arguments have been successfully parsed");
                    return 1;
                },
                (IEnumerable<Error> errs) =>
                {
                    WaitExitingCountdown();
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
            Trace.TraceInformation($"Got {credentialsDict.Count} credentials");
            if (credentialsDict.Where(t => t.Key == "IV" || t.Key == "AESPass" || t.Key == "Salt").Count() < 3)
            {
                Trace.TraceError("Necessary cryptographic input is absent in the provided entry in the KDBX.");
                WaitExitingCountdown();
                return;
            }

            Dictionary<string, string> salesForceSID = new Dictionary<string, string>(await GetSalesForceSessionId(credentialsDict));
            if (salesForceSID.Count == 0)
            {
                Trace.TraceError("Error getting SalesForce session ID. Exiting...");
                WaitExitingCountdown();
                return;
            }

            #region ChecksOfNeededFiles
            switch (workingMode)
            {
                case WorkingModes.Read:
                    listOfIds = (await GetListOfIds(salesForceSID, objectWithAttachments)).ToList();
                    if (listOfIds.Count != 0)
                    {
                        Trace.TraceInformation($"Got {listOfIds.Count} Ids in the {objectWithAttachments} object");
                    }
                    else
                    {
                        Trace.TraceError("Nothing to extract. Exiting...");
                        WaitExitingCountdown();
                        Environment.Exit(-2);
                    }
                    break;
                case WorkingModes.Write:
                case WorkingModes.Compare:
                    if (!File.Exists(resultFileName))
                    {
                        Trace.TraceError("Source file does not exist. Exiting...");
                        WaitExitingCountdown();
                        Environment.Exit(-3);
                    }
                    break; ;
            }
            #endregion

            #region CryptographicStuff
            SymmetricAlgorithm cipher = SymmetricAlgorithm.Create("AesManaged");
            cipher.Mode = CipherMode.CBC;
            cipher.Padding = PaddingMode.PKCS7;
            cipher.IV = Convert.FromBase64String(credentialsDict["IV"].ReadString());
            Byte[] passwordKey = NewPasswordKey(SecureStringExtension.ToSecureString(credentialsDict["AESPass"].ReadString()),
                credentialsDict["Salt"].ReadString());
            #endregion

            #region StartWorkers
            List<Task> tasks = new List<Task>();
            switch (workingMode) 
            {
                case WorkingModes.Read:
                    using (TextWriter resultStream = TextWriter.Synchronized(new StreamWriter(resultFileName, false, Encoding.ASCII)))
                    {
                        Trace.TraceInformation($"Initiating {numberOfThreads} workers to read data.");
                        for (int i = 0; i < numberOfThreads; i++)
                        {
                            tasks.Add(Task.Run(
                                () => doWork(listOfIds.ToList(), salesForceSID, objectWithAttachments, cipher.CreateEncryptor(passwordKey, cipher.IV), resultStream)));
                        }
                        Task.WaitAll(tasks.ToArray());
                    }
                    break;
                case WorkingModes.Write:
                    minSizeQueue = new MinSizeQueue<KeyValuePair<string, string>>(numberOfThreads);
                    _ = FillQueue();
                    Trace.TraceInformation($"Initiating {numberOfThreads} workers to write data.");
                    for (int i = 0; i < numberOfThreads; i++)
                    {
                        tasks.Add(Task.Run(
                            () => doWork(minSizeQueue, salesForceSID, objectWithAttachments, cipher.CreateDecryptor(passwordKey, cipher.IV))));
                    }
                    Task.WaitAll(tasks.ToArray());
                    break;
                case WorkingModes.Compare:
                    minSizeQueue = new MinSizeQueue<KeyValuePair<string, string>>(numberOfThreads);
                    _ = FillQueue();
                    using (TextWriter resultStream = TextWriter.Synchronized(new StreamWriter(pathToComparisonResults, false, Encoding.ASCII)))
                    {
                        Trace.TraceInformation($"Initiating {numberOfThreads} workers to compare data.");
                        for (int i = 0; i < numberOfThreads; i++)
                        {
                            tasks.Add(Task.Run(
                                () => doWork(minSizeQueue, salesForceSID, objectWithAttachments, cipher.CreateDecryptor(passwordKey, cipher.IV), resultStream)));
                        }
                        Task.WaitAll(tasks.ToArray());
                    }
                    break;
            }
            Trace.TraceInformation("All threads complete");
            WaitExitingCountdown();
        }
        #endregion StartWorkers

        #region Methods
        private static Task FillQueue()
        {
            return Task.Factory.StartNew(() =>
            {
                using (StreamReader reader = new StreamReader(resultFileName))
                {
                    int i = 1;
                    string line;
                    Regex reg = new Regex(@"^[a-zA-Z\d]{18},");
                    while (true)
                    {
                        line = reader.ReadLine();
                        if (line == null)
                        {
                            minSizeQueue.Close();
                            break;
                        }
                        else if (reg.Match(line).Captures.Count == 0)
                        {
                            Trace.TraceWarning($"Row #{i++} contains malformatted id");
                            continue;
                        }
                        string[] strs = line.Split(',');
                        if (!IsBase64String(strs[1]))
                        {
                            Trace.TraceWarning($"Row #{i++} contains malformatted Base64 body");
                            continue;
                        }
                        minSizeQueue.Enqueue(new KeyValuePair<string, string>(strs[0], strs[1]));
                        i++;
                    }
                }
            });
        }
        private static Byte[] NewPasswordKey(SecureString password, string salt)
        {
            int iterations = 1000;
            int keySize = 256;
            Rfc2898DeriveBytes PasswordDeriveBytes = new Rfc2898DeriveBytes(Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(password)),
                Encoding.ASCII.GetBytes(salt), iterations, HashAlgorithmName.SHA256);
            return PasswordDeriveBytes.GetBytes(keySize / 8);
        }

        private static async Task<IEnumerable<string>> GetListOfIds(IDictionary<string, string> dic, string obj)
        {
            HttpResponseMessage listOfIds = new HttpResponseMessage();
            List<string> lst = new List<string>();
            
            Uri requestUri = new Uri(dic["serverUrl"] + "/query/?q=SELECT+Id+FROM+" + obj);
            
            while (true)
            {

                listOfIds = await ReadFromSalesForce(requestUri, dic, HttpMethod.Get, null);

                if (listOfIds.StatusCode != HttpStatusCode.OK)
                {
                    Trace.TraceWarning("Request of Ids returned {0}", listOfIds.StatusCode);
                    break;
                }

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

        //A worker for Read mode
        private static async Task doWork(ICollection<string> listOfIds, IDictionary<string,string> creds, string obj, ICryptoTransform cryptoTrans, TextWriter writer)
        {
            SynchronizedIds psid = new SynchronizedIds();
            int currentId;
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            do
            {
                currentId = psid.GetCurrentID();
                if (currentId < listOfIds.Count && !(listOfIds.ToList())[currentId].Equals(string.Empty))
                {
                    HttpResponseMessage resp = await ReadFromSalesForce(
                        new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + (listOfIds.ToList())[currentId] + "/Body")
                        , creds, HttpMethod.Get, null);
                    if (resp != null && resp.Content != null && resp.StatusCode == HttpStatusCode.OK)
                    {
                        using (MemoryStream ms = resp.Content.ReadAsStreamAsync().Result as MemoryStream)
                        {
                            Trace.TraceInformation(
                                  $"Input #{currentId} with ID:{(listOfIds.ToList())[currentId]} has resulted in {ms.Length} bytes read by a thread #{guid}");
                            using (MemoryStream stream = new MemoryStream())
                            {
                                using (CryptoStream cstream = new CryptoStream(stream, cryptoTrans, CryptoStreamMode.Write))
                                {
                                    cstream.Write(ms.ToArray(), 0, Convert.ToInt32(ms.Length));
                                    cstream.FlushFinalBlock();
                                    byte[] encrypted = stream.ToArray();
                                    writer.WriteLine(listOfIds.ToList()[currentId] + "," + Convert.ToBase64String(encrypted));
                                }
                            }
                        }
                    }
                    else
                    {
                        Trace.TraceError($"{(listOfIds.ToList())[currentId]} failed to read. Sending to the queue again");
                        listOfIds.Append((listOfIds.ToList())[currentId]);
                    }
                    continue;
                }
                break;
            } while (true);
            Trace.TraceInformation($"A worker {guid} has finished the work.");
        }

        //A worker for Write mode
        private static async Task doWork(MinSizeQueue<KeyValuePair<string,string>> queue, IDictionary<string, string> creds, string obj, ICryptoTransform cryptoTrans) 
        {
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            while (true) 
            {
                KeyValuePair<string, string> att;
                if (minSizeQueue.TryDequeue(out att))
                {
                    byte[] valueBytes = null;
                    try
                    {
                        valueBytes = Convert.FromBase64String(att.Value);
                    }
                    catch
                    {
                        Trace.TraceError($"Error decoding Base64 value for {att.Key}");
                        continue;
                    }
                    if (valueBytes.Length > 0) 
                    {
                        //MemoryStream to store decrypted body to
                        using (MemoryStream stream = new MemoryStream(Convert.FromBase64String(att.Value)))
                        {
                            using (CryptoStream cstream = new CryptoStream(stream, cryptoTrans, CryptoStreamMode.Read))
                            {
                                byte[] decrypted = new byte[valueBytes.Length];
                                try
                                {
                                    int bytesRead = cstream.Read(decrypted, 0, valueBytes.Length);
                                    if (bytesRead > 0)
                                    {
                                        string decryptedValue = Convert.ToBase64String(decrypted);
                                        string json = "{\"Body\":\"" + decryptedValue +"\"}"; // JsonConvert.SerializeObject(attachment);
                                        HttpResponseMessage response = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + att.Key),
                                            creds, new HttpMethod("PATCH"), json);
                                        if (response != null && response.Content != null && response.StatusCode == HttpStatusCode.OK)
                                        {
                                            Trace.TraceInformation($"{att.Key} has been successfully updated by {guid}.");
                                        }
                                        else if (response.StatusCode == HttpStatusCode.NoContent)
                                        {
                                            Trace.TraceInformation($"{att.Key}'s content has obviously been modified by {guid}, though \"no content\" has been returned.");
                                        }
                                        else
                                        {
                                            Trace.TraceError($"{att.Key} failed to update by {guid}. {response?.StatusCode}");
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Trace.TraceError($"{ex.Message}\noccured while trying to update {att.Key} from {guid}");
                                }
                            }
                        } 
                    }
                    else
                    {
                        Trace.TraceError($"{att.Key} didn't give any body for writing.");
                    }
                }
                else 
                {
                    minSizeQueue.Close();
                    break; 
                }
            }
            Trace.TraceInformation($"A worker {guid} has finished the work.");
        }

        //A worker for Compare mode
        private static async Task doWork(MinSizeQueue<KeyValuePair<string, string>> queue, IDictionary<string, string> creds, string obj, ICryptoTransform cryptoTrans, TextWriter writer)
        {
            SynchronizedIds psid = new SynchronizedIds();
            int currentId;
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            while (true)
            {
                currentId = psid.GetCurrentID();
                KeyValuePair<string, string> att;
                if (minSizeQueue.TryDequeue(out att))
                {
                    byte[] valueBytes = null;
                    try
                    {
                        valueBytes = Convert.FromBase64String(att.Value);
                    }
                    catch
                    {
                        Trace.TraceError($"Error decoding Base64 value for {att.Key}");
                        continue;
                    }
                    if (valueBytes.Length > 0)
                    {
                        using (MemoryStream stream = new MemoryStream(Convert.FromBase64String(att.Value)))
                        {
                            using (CryptoStream cstream = new CryptoStream(stream, cryptoTrans, CryptoStreamMode.Read))
                            {
                                byte[] decrypted = new byte[valueBytes.Length];
                                try
                                {
                                    int bytesRead = cstream.Read(decrypted, 0, valueBytes.Length);
                                    if (bytesRead > 0)
                                    {
                                        string decryptedValue = Convert.ToBase64String(decrypted);
                                        HttpResponseMessage response = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + att.Key + "/Body"),
                                            creds, HttpMethod.Get, null);
                                        if(response != null && response.Content != null && response.StatusCode == HttpStatusCode.OK)
                                        {
                                            using (MemoryStream ms = new MemoryStream())
                                            {
                                                response.Content.ReadAsStreamAsync().Result.CopyTo(ms);
                                                byte[] res = ms.ToArray();
                                                Array.Resize<byte>(ref decrypted, res.Length);
                                                if (res.SequenceEqual(decrypted))
                                                {
                                                    Trace.TraceInformation($"#{currentId} - {att.Key} is Equal from {guid}.");
                                                    writer.WriteLine(att.Key + ",EQ");
                                                }
                                                else Trace.TraceInformation($"#{currentId} - {att.Key} is OK from {guid}.");
                                            }
                                        }
                                        else
                                        {
                                            Trace.TraceWarning($"#{currentId} - {att.Key} failed to read from {guid}.");
                                            writer.WriteLine(att.Key + ",SF_ERROR");
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Trace.TraceError($"{ex.Message}\noccured while trying to compare {att.Key} from {guid}");
                                }
                            }
                        }
                    }
                }
                else
                {
                    minSizeQueue.Close();
                    break;
                }
            }
            Trace.TraceInformation($"A worker {guid} has finished the work.");
        }

        private static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);

        }

        private static IDictionary<string, ProtectedString> OpenKeePassDB (SecureString Password)
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
                Trace.TraceError($"Failed to open KeePassDb \n{ex.Message}");
            }
            finally
            {
                PwDB.Close();
            }
            //Delete key-value pairs where values are empty
            dict.Where(d=>d.Value.IsEmpty).ToList().ForEach(t=>dict.Remove(t.Key));
            return dict;
        }
    
        private static async Task<IDictionary<string, string>> GetSalesForceSessionId(IDictionary<string, ProtectedString> creds)
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
                Trace.TraceInformation("Sending a request to SF for log-in...");
                HttpResponseMessage msg = await client.SendAsync(httpRequestMessage, HttpCompletionOption.ResponseHeadersRead);
                if (msg.IsSuccessStatusCode)
                {
                    Trace.TraceInformation("Got successful login response");
                    x.LoadXml(msg.Content.ReadAsStringAsync().Result);
                }
                else
                {
                    Trace.TraceError("SalesForce login failed");
                    return new Dictionary<string, string>();
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.Message);
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
                    case "userInfo":
                        dict.Add("sessionSecondsValid", (n["sessionSecondsValid"]).InnerText);
                        Trace.TraceInformation($"The session will be valid for {dict["sessionSecondsValid"]} seconds!");
                        break;
                }
            }
            return dict;
        }

        private static async Task<HttpResponseMessage> ReadFromSalesForce(Uri requestUri, IDictionary<string,string> dic, HttpMethod method, string content)
        {
            HttpResponseMessage response = new HttpResponseMessage();
            List<string> lst = new List<string>();
            HttpRequestMessage msg = new HttpRequestMessage
            {
                Method = method,
                RequestUri = requestUri,
                Headers = {
                    { HttpRequestHeader.Accept.ToString(), "application/json" },
                    { "Authorization", "Bearer " + dic["sessionId"] }
                }
            };
            if (content != null)
            {
                msg.Content = new StringContent(content, Encoding.UTF8, "application/json");
            }

            try
            {
                response = await client.SendAsync(msg, HttpCompletionOption.ResponseContentRead);
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.Message);
            }
            return response;
        }
        
        private static void WaitExitingCountdown()
        {
            int i = waittime.Seconds;
            Task.Factory.StartNew(() =>
            {
                Timer timer = new Timer(new TimerCallback((e) =>
                {
                    Console.Write("\rWait for {0} seconds or press any key to exit...", (i--).ToString("D2"));
                }), null, 1, 1000);
            });
            Task.Factory.StartNew(() => Console.ReadKey()).Wait(waittime);
        }
        #endregion Methods
    }

    class Options
    //https://github.com/gsscoder/commandline/wiki/Latest-Version
    {
        [Option('m', "workmode",
            Default = WorkingModes.Read,
            HelpText ="Set the working mode.\nRead - to read the data from the SF org and store them into a file;" +
            "\nwrite - to read the data from encrypted file and store them back into the SF org;\ncompare - to compare the data from the encrypted file and SF org.")]

        public WorkingModes WorkMode { get; set; }

        [Option('d', "salesforcedomain",
            Default = "test", MetaValue = "test",
            HelpText = "Represents a domain used to log into SalesForce from, e.g. https://test.salesforce.com")]
        public string SalesForceDomain { get; set; }

        [Option('g', "groupname", Required = true, MetaValue ="EPAM",
            HelpText = "Gives the name of the group in the KeePass file where to look for the entry")]
        public string GroupName { get; set; }

        [Option('e', "entryname", Required = true, MetaValue = "EPAM",
            HelpText = "Gives the name of the Entry within the group in the KeePass file with necessary credentials")]
        public string EntryName { get; set; }

        [Option('k', "kdbxpath", Required = true,
            HelpText = "Sets the path to the KeePass file with the credentials. The file must not be key-file protected!")]
        public string KDBXPath { get; set; }

        [Option('o', "sfobject", Default = SFObjectsWithAttachments.Document,
            HelpText ="Points out which SalesForce object the body of attachments should be taken from",
            MetaValue ="Document")]
        public SFObjectsWithAttachments SFObject { get; set; }

        [Option('t',"targetfile",
            HelpText ="Sets the path to the target (source in case of write) file to store (to read) encrypted attachments to (from)")]
        public string ecryptedAttachmentsTargetFile { get; set; }

        [Option('n',"threads", Default = 2, MetaValue ="2",
            HelpText ="Sets the number of concurrent threads")]
        public int numberOfWorkingThreads { get; set; }

        [Option ('c', "comppath",
            HelpText ="Sets path to the file with comparison results",
            MetaValue ="D:\\Doc_comp_res.dat")]
        public string comparisonResultsFilePath { get; set; }

        [Option('l', "logfile",
            HelpText ="Sets the path to the logging file in additon to logging to the Console")]
        public string logFilePath { get; set; }

        [Option('x',"logtoconsole", Default = 1,
            HelpText ="Switches logging to Console mode on(<>0)/off(0). Might be useful since it doesn't waste time on UI output, though makes survey possible only through log file (if any provided).",
            MetaValue = "1")]
        public int logToConsole { get; set; }
    }

    enum SFObjectsWithAttachments
    {
        Attachment,
        Document
    }

    enum WorkingModes
    {
        Read,
        Write,
        Compare
    }
}