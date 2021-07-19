using AsyncSalesForceAttachments;
using CommandLine;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;
using KeePassLib.Cryptography.PasswordGenerator;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using RepresentativeSubset;
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
        private static string filter;
        private static int numberOfThreads;
        private static HttpClient client = new HttpClient();
        private static ConsoleKeyInfo key;
        private static WorkingModes workingMode;
        private static List<string> listOfIds = null;
        private static MinSizeQueue<KeyValuePair<string, string>> minSizeQueue;
        private static TimeSpan waittime = TimeSpan.FromSeconds(30);
        private static ConsoleTraceListener consoleTraceListener = new ConsoleTraceListener();
        private static bool useWindowsLogon = false;
        private static SymmetricAlgorithm cipher;
        private static Dictionary<string, ProtectedString> credentialsDict;
        #endregion fields
        [MTAThread]
        static async Task Main(string[] args)
        {
            //Parse the arguments
            int result = Parser.Default.ParseArguments<Options>(args)
                .MapResult(
                (Options opt) =>
                {
                    domainName = opt.SalesForceDomain;
                    groupName = opt.GroupName;
                    entryName = opt.EntryName;
                    pathToKeePassDb = opt.KDBXPath;
                    objectWithAttachments = Enum.GetName(typeof(SFObjectsWithAttachments), opt.SFObject);
                    resultFileName = opt.EcryptedAttachmentsTargetFile ?? "encrypted_" + objectWithAttachments + ".dat";
                    workingMode = opt.WorkMode;
                    numberOfThreads = opt.NumberOfWorkingThreads;
                    useWindowsLogon = opt.UseWindowsAccount == 1;
                    if (opt.LogFilePath != null && !opt.LogFilePath.Equals(String.Empty))
                    {
                        Trace.Listeners.Add(new TextWriterTraceListener(opt.LogFilePath, "Backup_fileTracer"));
                        Trace.Listeners["Backup_fileTracer"].TraceOutputOptions |= TraceOptions.DateTime;
                    }
                    if (opt.LogToConsole != 0) Trace.Listeners.Add(consoleTraceListener);
                    Trace.AutoFlush = true;
                    Trace.Listeners.Remove("Default");
                    if (workingMode == WorkingModes.Compare &&
                        (opt.ComparisonResultsFilePath == null || opt.ComparisonResultsFilePath.Equals(String.Empty)))
                    {
                        Trace.TraceError($"If workmode is set to compare then comparison file must be provided.");
                        WaitExitingCountdown(waittime);
                        Environment.Exit((int)ExitCodes.ComparisonFileIsAbsentError);
                        return 0;
                    }
                    else
                    {
                        pathToComparisonResults = opt.ComparisonResultsFilePath;
                        if (workingMode == WorkingModes.Read)
                        {
                            filter = "+WHERE+" + opt.ReadModeFilter;
                        }
                        if (workingMode == WorkingModes.Subset)
                        {
                            filter = opt.ReadModeFilter;
                        }
                    }
                    Trace.TraceInformation("Arguments have been successfully parsed");
                    return 1;
                },
                (IEnumerable<Error> errs) =>
                {
                    //Let the user to read the error message and exit after waittime expires
                    WaitExitingCountdown(waittime);
                    Environment.Exit((int)ExitCodes.ArgumentParsingError);
                    return 0;
                });

            //Open KeePass (needed for every operation) and store credentials in the dictionary
            //This is done with regard that the KDBX file could be protected by Windows credentials
            //starting from some new versions as well.
            credentialsDict = new Dictionary<string, ProtectedString>(OpenKeePassDB(
                    useWindowsLogon ? (new SecureString()) : ReadPasswordFromConsole(), useWindowsLogon));
            Trace.TraceInformation($"Got {credentialsDict.Count} credentials");

            //Check whether the number of credentials and their names are enough depending on the workmode
            if (credentialsDict.Where(t => t.Key == "IV" || t.Key == "AESPass" || t.Key == "Salt").Count() < 3
                && workingMode != WorkingModes.Prepare
                && workingMode != WorkingModes.Subset)
            {
                Trace.TraceError("Necessary cryptographic input is absent in the provided entry in the KDBX.");
                WaitExitingCountdown(waittime);
                Environment.Exit((int)ExitCodes.CryptographicStuffAbsenseError);
                return;
            }
            else if (workingMode == WorkingModes.Prepare)
            {
                Trace.TraceInformation("Preparation of KDBX has been successfully completed");
                WaitExitingCountdown(waittime);
                return;
            }
            else if (workingMode == WorkingModes.Subset
                 && credentialsDict.Where(t => t.Key == "UserName" || t.Key == "Password").Count() == 2)
            {
                Trace.TraceInformation("Got username and password from the given KeePass file");
            }
            else
            {
                Trace.TraceError("Unknown error occured");
                Environment.Exit((int)ExitCodes.UnknownError);
                return;
            }

            //Connect to the SalesForce org and store the results in a dictionary
            Dictionary<string, string> salesForceSID = new Dictionary<string, string>(await GetSalesForceSessionId(credentialsDict));
            if (salesForceSID.Count == 0)
            {
                Trace.TraceError("Error getting SalesForce session ID. Exiting...");
                Environment.Exit((int)ExitCodes.GettingSalesForceSessionIDError);
                WaitExitingCountdown(waittime);
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
                        WaitExitingCountdown(waittime);
                        Environment.Exit(-2);
                    }
                    break;
                case WorkingModes.Write:
                case WorkingModes.Compare:
                    if (!File.Exists(resultFileName))
                    {
                        Trace.TraceError("Source file does not exist. Exiting...");
                        WaitExitingCountdown(waittime);
                        Environment.Exit(-3);
                    }
                    break;
                case WorkingModes.Subset:
                    listOfIds = new List<string>();
                    break;
                default:
                    break;
            }
            #endregion
            //Fill the cryptographic stuff only if it is needed, i.e. the working modes need it
            if (workingMode != WorkingModes.Subset) cipher = PrepareCryptographicStuff(credentialsDict);

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
                                () => doWork(listOfIds.ToList(), salesForceSID, objectWithAttachments, cipher.CreateEncryptor(Convert.FromBase64String(credentialsDict["pwdKey"].ReadString()), cipher.IV), resultStream)));
                        }
                        Task.WaitAll(tasks.ToArray());
                    }
                    break;
                case WorkingModes.Write:
                    minSizeQueue = new MinSizeQueue<KeyValuePair<string, string>>(numberOfThreads);
                    _ = FillQueue(resultFileName);
                    Trace.TraceInformation($"Initiating {numberOfThreads} workers to write data.");
                    for (int i = 0; i < numberOfThreads; i++)
                    {
                        tasks.Add(Task.Run(
                            () => doWork(minSizeQueue, salesForceSID, objectWithAttachments, cipher.CreateDecryptor(Convert.FromBase64String(credentialsDict["pwdKey"].ReadString()), cipher.IV))));
                    }
                    Task.WaitAll(tasks.ToArray());
                    break;
                case WorkingModes.Compare:
                    minSizeQueue = new MinSizeQueue<KeyValuePair<string, string>>(numberOfThreads);
                    _ = FillQueue(resultFileName);
                    using (TextWriter resultStream = TextWriter.Synchronized(new StreamWriter(pathToComparisonResults, false, Encoding.ASCII)))
                    {
                        Trace.TraceInformation($"Initiating {numberOfThreads} workers to compare data.");
                        for (int i = 0; i < numberOfThreads; i++)
                        {
                            tasks.Add(Task.Run(
                                () => doWork(minSizeQueue, salesForceSID, objectWithAttachments, 
                                    cipher.CreateDecryptor(Convert.FromBase64String(credentialsDict["pwdKey"].ReadString()),
                                    cipher.IV), resultStream)));
                        }
                        Task.WaitAll(tasks.ToArray());
                    }
                    break;
                case WorkingModes.Subset:
                    listOfIds = (await GetListOfObjects(salesForceSID, filter)).ToList<string>();

                    //If target folder or file path has been given store absolute folder path to the dictionary
                    if (pathToComparisonResults != null && !pathToComparisonResults.Equals(String.Empty))
                    {
                        try
                        {
                            salesForceSID.Add("targetPath", Path.GetDirectoryName(pathToComparisonResults));
                        }
                        catch { }
                    }
                    Trace.TraceInformation($"Initiating {numberOfThreads} workers to create representative subsets of the data.");
                    for (int i = 0; i < numberOfThreads; i++)
                    {
                        tasks.Add(Task.Run(
                            () => doWork(listOfIds, salesForceSID)));
                    }
                    Task.WaitAll(tasks.ToArray());
                    break;
                default:
                    break;
            }
            Trace.TraceInformation("All threads have completed");
            WaitExitingCountdown(waittime);
        }
        #endregion StartWorkers

        /// <summary>
        /// Gets the list of the objects from the SalesForce org as a JSON response
        /// parses it and returns filtered list of objects names to be further processed
        /// by the system.
        /// Non-updateable objects among them almost all system ones are skipped
        /// __Share & __Tag objects are skipped as well.
        /// </summary>
        /// <param name="dic">A IDictionary collection with credentials</param>
        /// <param name="flt">A nullable filter string, must contain pipe-separated names of the objects that will then be processed
        /// if found among those present in the SF org</param>
        /// <returns></returns>
        #region Methods
        private static async Task<IEnumerable<string>> GetListOfObjects(IDictionary<string,string> dic, string flt)
        {
            Trace.TraceInformation("Getting the list of the objects, please, wait it may take a little while...");
            HttpResponseMessage listOfObjects = await ReadFromSalesForce(new Uri(dic["serverUrl"] + "/sobjects/"), 
                dic, HttpMethod.Get, null);
            JArray arr = JArray.Parse(JObject.Parse(await listOfObjects.Content.ReadAsStringAsync())["sobjects"].ToString());
            Trace.TraceInformation($"Got totally {arr.Count} objects");
            Trace.TraceInformation($"Amongst them only {arr.Where(t => t["updateable"].ToString().Equals("True")).Count()} are updatable");
            
            //Compose an array to be used for exclusion of __Share objects since they cannot contain any sensitive information
            IEnumerable<JToken> excludeArray = arr.Where(t => t["name"].ToString().EndsWith("__Share"));
            excludeArray.Concat(arr.Where(t => t["name"].ToString().EndsWith("__Tag")));
            //
            // Others exclusions must be added in the same manner here
            //

            List<string> lst = new List<string>();
            if (flt == null)
            {
                foreach (JToken j in arr.Where(t => t["updateable"].ToString().Equals("True"))
                    .Except(excludeArray))
                {
                    Trace.TraceInformation("No filter is given adding all the possible objects to the list");
                    lst.Add(j["name"].ToString());
                }
            }
            else
            {
                foreach (JToken j in arr.Where(t => t["updateable"].ToString().Equals("True"))
                    .Except(excludeArray)
                    .Join(filter.Split('|'),
                    p => p["name"].ToString(),
                    t => t,
                    (p, t) => t))
                {
                    Trace.TraceInformation($"Filter is active; adding {j} to the list of the objects to be processed");
                    lst.Add(j.ToString());
                }
            }
            Trace.TraceInformation($"Total number of objects to be processes is {lst.Count}");
            return lst;
        }

        private static SymmetricAlgorithm PrepareCryptographicStuff(IDictionary<string, ProtectedString> creds)
            {
                SymmetricAlgorithm cphr = SymmetricAlgorithm.Create("AesManaged");
                cphr.Mode = CipherMode.CBC;
                cphr.Padding = PaddingMode.PKCS7;
                cphr.IV = Convert.FromBase64String(credentialsDict["IV"].ReadString());
                Byte[] passwordKey = NewPasswordKey(SecureStringExtension.ToSecureString(creds["AESPass"].ReadString()),
                    creds["Salt"].ReadString());
                creds.Add("pwdKey", new ProtectedString(true, Convert.ToBase64String(passwordKey, 0, passwordKey.Length)));
                return cphr;
            }

        private static SecureString ReadPasswordFromConsole()
        {
            SecureString secStr = new SecureString();
            Console.Write("Enter password for KeePass: ");
            do
            {
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace)
                {
                    // Append the character to the password.
                    if (key.Key != ConsoleKey.Enter) secStr.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
                else
                {
                    if (secStr.Length > 0)
                    {
                        secStr.RemoveAt(secStr.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                // Exit if Enter key is pressed.
            } while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return secStr;
        }

        /// <summary>
        /// Fills the queue with Ids and the encrypted content of the backup file
        /// </summary>
        /// <param name="resultFN">path to the encrypted backup</param>
        /// <returns></returns>
        private static Task FillQueue(string resultFN)
        {
            return Task.Factory.StartNew(() =>
            {
                using (StreamReader reader = new StreamReader(resultFN))
                {
                    int i = 1;
                    string line;
                    //A check so as to ensure all Ids are the standard 18-characters SF ids
                    Regex reg = new Regex(@"^[a-zA-Z\d]{18},");
                    while (true)
                    {
                        line = reader.ReadLine();
                        if (line == null)
                        {
                            //Completes the loading of the queue and notifies it to close if all its workers have finished
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
        
        /// <summary>
        /// Creates new password key basing on the given password and salt
        /// </summary>
        /// <param name="password">A secureString with the password</param>
        /// <param name="salt">A string with the salt</param>
        /// <returns></returns>
        private static Byte[] NewPasswordKey(SecureString password, string salt)
        {
            int iterations = 1000;
            int keySize = 256;
            Rfc2898DeriveBytes PasswordDeriveBytes = new Rfc2898DeriveBytes(Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(password)),
                Encoding.ASCII.GetBytes(salt), iterations, HashAlgorithmName.SHA256);
            return PasswordDeriveBytes.GetBytes(keySize / 8);
        }

        /// <summary>
        /// Gets the list of IDs from the SF org's object obj
        /// </summary>
        /// <param name="dic">Contains necessary stuff to connect to the SF org</param>
        /// <param name="obj">Contains the name of the object</param>
        /// <returns></returns>
        private static async Task<IEnumerable<string>> GetListOfIds(IDictionary<string, string> dic, string obj)
        {
            HttpResponseMessage listOfIds = new HttpResponseMessage();
            List<string> lst = new List<string>();
            Uri requestUri = null;

            try
            {
                requestUri = new Uri(dic["serverUrl"] + "/query/?q=SELECT+Id+FROM+" + obj + filter);
                Trace.TraceInformation($"Uri to get Ids {requestUri}");
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.Message + "\n from GetListofIds");
            }

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

                try
                {
                    if (j["nextRecordsUrl"] != null)
                    {
                        requestUri = new Uri(dic["serverUrl"] + "/query"
                            + j["nextRecordsUrl"].ToString().Substring(j["nextRecordsUrl"].ToString().LastIndexOf('/')));
                        Trace.TraceInformation($"Getting IDs from the {requestUri}");
                    }
                    else break;
                }
                catch (Exception ex)
                {
                    Trace.TraceError(ex.Message + "\n" + dic["serverUrl"]);
                }
            }
            return lst;
        }

        /// <summary>
        /// A worker for Subset mode; creates subsets from the SalesForce org
        /// </summary>
        /// <param name="listOfIds">List of objects to be processed</param>
        /// <param name="creds">credentials</param>
        /// <returns></returns>
        private static async Task doWork(ICollection<string> listOfIds, IDictionary<string, string> creds)
        {
            SynchronizedIds psid = new SynchronizedIds();
            int currentId;
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            HttpResponseMessage resp = null;
            do
            {
                currentId = psid.GetCurrentID();
                if (currentId < listOfIds.Count && !(listOfIds.ToList())[currentId].Equals(string.Empty))
                {
                    string currObject = (listOfIds.ToList())[currentId];
                    try
                    {
                        Trace.TraceInformation($"Sending request to SF org from {guid} to describe {currObject}");
                        resp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" +currObject + "/describe")
                            , creds, HttpMethod.Get, null);
                    }
                    catch (Exception ex)
                    {
                        Trace.TraceError("An exception occured while working in subset mode.\n" +
                            ex.Message);
                    }

                    int initialSleep = 3;
                    if (resp != null && resp.Content != null && resp.StatusCode == HttpStatusCode.OK)
                    {
                        JArray arrFields = JArray.Parse(JObject.Parse(await resp.Content.ReadAsStringAsync())["fields"].ToString());
                        Trace.TraceInformation($"{guid} got {arrFields.Count} fields described in the {currObject}");

                        var jobJsonObj = new
                        {
                            operation = "query",
                            query = "SELECT Id," +
                            //A selector condition must be added here
                            arrFields.Where(t => t["updateable"].ToString().Equals("True"))
                                .Select(o => o["name"].ToString())
                                .Aggregate("", (c, n) => $"{c}, {n}")
                                .TrimStart(',')
                            + " FROM " + currObject,
                            contentType = "CSV",
                            columnDelimiter = "PIPE",
                            lineEnding = "CRLF"
                        };
                        string jobLoad = JsonConvert.SerializeObject(jobJsonObj);

                       HttpResponseMessage jobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query")
                           , creds, HttpMethod.Post, jobLoad);

                        if(jobresp != null && jobresp.Content != null && jobresp.StatusCode == HttpStatusCode.OK)
                        {
                            JObject jobInfo = JObject.Parse(await jobresp.Content.ReadAsStringAsync());
                            Trace.TraceInformation($"{guid} has queued a job {jobInfo["id"]} to get the data from the {currObject} object");
                            while (jobInfo["state"].ToString().Equals("InProgress") || jobInfo["state"].ToString().Equals("UploadComplete"))
                            {
                                //Every time the loop will wait twice as longer as the previous time
                                initialSleep *= 2;
                                Trace.TraceInformation($"Sleep for {initialSleep} seconds then check results...");
                                Thread.Sleep(initialSleep * 1000);
                                //Requests for job completion or failure
                                jobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query/" + jobInfo["id"])
                                    , creds, HttpMethod.Get);
                                if (jobresp != null && jobresp.Content != null && jobresp.StatusCode == HttpStatusCode.OK)
                                {
                                    jobInfo = JObject.Parse(await jobresp.Content.ReadAsStringAsync());
                                }
                                else
                                {
                                    jobInfo["state"] = "UnknowError";
                                    break;
                                }
                            }
                            if (jobInfo["state"].ToString().Equals("JobComplete"))
                            {
                                //The job has successfully completed
                                //Need to read the CSV data
                                jobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query/" + jobInfo["id"] + "/results")
                                    , creds, HttpMethod.Get, accepts: "txt/csv");
                                //And to store the data in a CSV file
                                if (true)
                                {
                                    string path;
                                    bool pathExists = creds.TryGetValue("targetPath", out path);
                                    if (pathExists)
                                    {
                                        path = Path.Combine(path, $"{guid}_{currObject}.csv");
                                    }
                                    else
                                    {
                                        path = $"{guid}_{currObject}.csv";
                                    }
                                    using (StreamWriter streamWriter =
                                        new StreamWriter(new FileStream(path,
                                        FileMode.CreateNew, FileAccess.Write), Encoding.UTF8)
                                        )
                                    {
                                        byte[] b = await jobresp.Content.ReadAsByteArrayAsync();
                                        streamWriter.Write(Encoding.UTF8.GetString(b));
                                    }
                                    Trace.TraceInformation($"{path} has been created");
                                }
                                else
                                {
                                    ;
                                }
                            }
                            else
                            {
                                Trace.TraceError($"Error processing Bulk job {jobInfo["id"]} for {currObject} with the state {jobInfo["state"]}");
                                continue;
                            }
                        }
                        else
                        {
                            Trace.TraceError($"Error creating Bulk job for {currObject}");
                            continue;
                        }
                    }
                    else
                    {
                        Trace.TraceError($"{currObject} failed to read. Sending to the queue again");
                        listOfIds.Append(currObject);
                    }
                    continue;
                }
                break;
            } while (true);
            Trace.TraceInformation($"A worker {guid} has finished the work.");
        }

        /// <summary>
        /// A worker for Read mode; reads the attachment content from the given (default) object of the SalesForce org, encrypts
        /// it using provided cryptographic stuff and stores it into the given shared Text Stream.
        /// </summary>
        /// <param name="queue">
        /// A queue of Key-Value pairs with Ids; the singleton storing the number of the current Id is used to refer to the queue
        /// </param>
        /// <param name="creds">A dictionary with sessionId and other stuff required to interact with SalesForce org</param>
        /// <param name="obj">The name of the SalesForce object</param>
        /// <param name="cryptoTrans">Cryptographic stuff necessary to encrypt the attachment content</param>
        /// <param name="writer">A shared text stream to store the encrypted data into</param>
        /// <returns></returns>
        private static async Task doWork(ICollection<string> listOfIds, IDictionary<string,string> creds, string obj, ICryptoTransform cryptoTrans, TextWriter writer)
        {
            SynchronizedIds psid = new SynchronizedIds();
            int currentId;
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            HttpResponseMessage resp = null;
            do
            {
                currentId = psid.GetCurrentID();
                if (currentId < listOfIds.Count && !(listOfIds.ToList())[currentId].Equals(string.Empty))
                {
                    try
                    {
                        resp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + (listOfIds.ToList())[currentId] + "/Body")
                            , creds, HttpMethod.Get, null);
                    }
                    catch (Exception ex)
                    {
                        Trace.TraceError("An exception occured while working in read mode.\n" +
                            ex.Message);
                    }

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

        /// <summary>
        /// A worker for Write mode; decrypts the content of the stored backup and writes it back to the SalesForce org.
        /// </summary>
        /// <param name="queue">
        /// A queue of Key-Value pairs with Ids; the singleton storing the number of the current Id is used to refer to the queue
        /// </param>
        /// <param name="creds">A dictionary with sessionId and other stuff required to interact with SalesForce org</param>
        /// <param name="obj">Cryptographic stuff necessary to encrypt the attachment content</param>
        /// <param name="cryptoTrans">A shared text stream to store the encrypted data into</param>
        /// <returns></returns>
        private static async Task doWork(MinSizeQueue<KeyValuePair<string,string>> queue, IDictionary<string, string> creds, string obj, ICryptoTransform cryptoTrans) 
        {
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            HttpResponseMessage response = null;
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
                                        string json = "{\"Body\":\"" + decryptedValue +"\"}";
                                        try
                                        {
                                            response = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + att.Key),
                                                creds, new HttpMethod("PATCH"), json);
                                        }
                                        catch (Exception ex)
                                        {
                                            Trace.TraceError("An exception occured while working in write mode.\n" +
                                                ex.Message);
                                        }

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

        /// <summary>
        /// A worker for Compare mode; reads the attachment content from the given (default) object of the SalesForce org and from the
        /// encrypted backup, decrypts it using provided cryptographic stuff, compares both values and stores the comparison results 
        /// into the given shared Text Stream.
        /// </summary>
        /// <param name="queue">
        /// A queue of Key-Value pairs with Ids; the singleton storing the number of the current Id is used to refer to the queue
        /// </param>
        /// <param name="creds">A dictionary with sessionId and other stuff required to interact with SalesForce org</param>
        /// <param name="obj">The name of the SalesForce object</param>
        /// <param name="cryptoTrans">Cryptographic stuff necessary to decrypt the backup content</param>
        /// <param name="writer">A shared text stream to store the comparison results into</param>
        /// <returns></returns>
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
                HttpResponseMessage response = null;

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
                                        try
                                        {
                                            response = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + att.Key + "/Body"),
                                                creds, HttpMethod.Get, null);
                                        }
                                        catch (Exception ex)
                                        {
                                            Trace.TraceError("An error occured while working in Compare mode.\n" +
                                                ex.Message);
                                        }

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

        private static IDictionary<string, ProtectedString> OpenKeePassDB (SecureString Password, bool UseWinLogon = false)
        {
            PwDatabase PwDB = new PwDatabase();
            IOConnectionInfo mioInfo = new IOConnectionInfo
            {
                Path = pathToKeePassDb
            };
            CompositeKey compositeKey = new CompositeKey();
            if (!UseWinLogon)
            {
                compositeKey.AddUserKey(new KcpPassword(Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(Password))));
            }
            else
            {
                compositeKey.AddUserKey(new KcpUserAccount());
            }
             
            IStatusLogger statusLogger = new NullStatusLogger();

            Dictionary<string, ProtectedString> dict = new Dictionary<string, ProtectedString>();

            try
            {
                PwDB.Open(mioInfo, compositeKey, statusLogger);
                PwObjectList<PwGroup> groups = PwDB.RootGroup.GetGroups(true);

                if (workingMode == WorkingModes.Prepare)
                {
                // Check whether the requested group already exists
                    if (!groups.Any(x => x.Name.Equals(groupName)))
                    {
                        PwDB.RootGroup.AddGroup(new PwGroup() { Name = groupName }, true);
                        Trace.TraceInformation($"The Group {groupName} has been added to KeePass DB");
                    }
                    PwGroup grp = PwDB.RootGroup.GetGroups(true).Where(x => x.Name.Equals(groupName)).First();
                // Check if the required entry doesn't exist in the group
                    if (!grp.GetEntries(false).Any(x => x.Strings.ReadSafe("Title").Equals(entryName)))
                    {
                        //Need to have a local variable for Protected dic
                        //otherwise the clause becomes too complecated for reading
                        ProtectedStringDictionary d = new ProtectedStringDictionary();
                        d.Set("Title", new ProtectedString(true, entryName));
#pragma warning disable CS0618 // Type or member is obsolete
                        //They tell it is obsolete and recommend to use any other constructor,
                        //but, actually, there's no other to be used.
                        grp.AddEntry(new PwEntry(grp, true, true) { Strings = d }, true);
#pragma warning restore CS0618 // Type or member is obsolete
                        Trace.TraceInformation($"The Entry {entryName} has been added to KeePass DB");
                    }
                    PwEntry ent= grp.GetEntries(false).Where(x => x.Strings.ReadSafe("Title").Equals(entryName)).First();
                //Create a value for password
                    ProtectedString aesPwd = new ProtectedString();
                    PwGenerator.Generate(out aesPwd, new PwProfile()
                        {
                            Length = 16,
                            CharSet = new PwCharSet(PwCharSet.LowerCase + 
                                                    PwCharSet.UpperCase + 
                                                    PwCharSet.Digits + 
                                                    PwCharSet.PrintableAsciiSpecial)
                        },
                            UTF8Encoding.UTF8.GetBytes(RndString.GetRandomString(16)),
                            new CustomPwGeneratorPool());
                //Create a vlaue for Salt
                    ProtectedString salt = new ProtectedString();
                    PwGenerator.Generate(out salt, new PwProfile()
                        {
                            Length = 26,
                            CharSet = new PwCharSet(PwCharSet.LowerCase + 
                                                    PwCharSet.UpperCase + 
                                                    PwCharSet.Digits + 
                                                    PwCharSet.PrintableAsciiSpecial)
                        },
                            UTF8Encoding.UTF8.GetBytes(RndString.GetRandomString(28)),
                            new CustomPwGeneratorPool());
                    ent.Strings.Set("AESpassword", new ProtectedString(true, aesPwd.ReadString()));
                    Trace.TraceInformation($"The value of the AESPass in the Entry {entryName} has been added to KeePass DB");
                    ent.Strings.Set("Salt", new ProtectedString(true, salt.ReadString()));
                    Trace.TraceInformation($"The value of the Salt in the Entry {entryName} has been added to KeePass DB");
                // Create IV
                    SymmetricAlgorithm cipher = SymmetricAlgorithm.Create("AesManaged");
                    cipher.Mode = CipherMode.CBC;
                    cipher.Padding = PaddingMode.PKCS7;
                    ent.Strings.Set("IV", new ProtectedString(true, Convert.ToBase64String(cipher.IV)));
                    Trace.TraceInformation($"The value of the IV in the Entry {entryName} has been added to KeePass DB");
                    PwDB.Save(statusLogger);
                // Add dummy values to the dictionary to pass the check in the end of the method
                    dict.Add("Salt", new ProtectedString(true, ent.Strings.ReadSafe("Salt")));
                    dict.Add("Password", new ProtectedString(true, "dummy"));
                    dict.Add("AESPass", new ProtectedString(true, ent.Strings.ReadSafe("AESpassword")));
                    dict.Add("UserName", new ProtectedString(true, "dummy"));
                    dict.Add("IV", new ProtectedString(true, ent.Strings.ReadSafe("IV")));
                    dict.Add("SecurityToken", new ProtectedString(true, "dummy"));
                }
                else
                {
                    foreach (PwGroup grp in groups)
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
    
        /// <summary>
        /// Tries to log in into the SalesForce org with given credentials        /// </summary>
        /// <param name="creds">
        /// A dictionary of ProtectedString with UserName and Password</param>
        /// <returns>
        /// A dictionary of strings with serverURL, sessionId, and number of seconds within during which the current session will be valid
        /// </returns>
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
                        n.FirstChild.InnerText = creds["Password"].ReadString() +
                            (creds.ContainsKey("SecurityToken") ? creds["SecurityToken"].ReadString():"");
                        break;
                }
            }

            var httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("https://" + domainName + ".salesforce.com/services/Soap/u/40.0"),
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
                        Trace.TraceInformation(dict["serverUrl"]);
                        break;
                    case "sessionId":
                        dict.Add("sessionId", n.FirstChild.InnerText);
                        break;
                    case "userInfo":
                        dict.Add("sessionSecondsValid", (n["sessionSecondsValid"]).InnerText);
                        Trace.TraceInformation($"The session will be valid for {dict["sessionSecondsValid"]} seconds!");
                        break;
                }
            }

            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri(dict["serverUrl"].Split(new char[] { '/' }).Take(3).Aggregate("", (c, n) => $"{c}/{n}").TrimStart('/') 
                + "/services/data/"),
                Headers = {
                    { HttpRequestHeader.Accept.ToString(), "application/json" }
                }
            };

            try
            {
                Trace.TraceInformation("Looking for the latest API...");
                HttpResponseMessage msg = await client.SendAsync(httpRequestMessage, HttpCompletionOption.ResponseHeadersRead);
                if (msg.IsSuccessStatusCode)
                {
                    Trace.TraceInformation("Got response from the server");
                    string v = await msg.Content.ReadAsStringAsync();
                    JArray arr = JArray.Parse(v);
                    Trace.TraceInformation($"Got the last version of the API: {arr.Last["version"]}");
                    dict.Add("latestAPIVersion", arr.Last["version"].ToString());
                    string servUrl = dict["serverUrl"];
                    dict.Remove("serverUrl");

                    Regex regex = new Regex("v\\d{1,2}\\.\\d{1}");
                    dict.Add("serverUrl", regex.Replace(servUrl, "v" + arr.Last["version"].ToString()));
                }
                else
                {
                    Trace.TraceError("Error getting the latest version of the API");
                    return dict;
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError(ex.Message);
                return dict;
            }

            return dict;
        }

        /// <summary>
        /// Reads from the SalesForce org after successful login
        /// </summary>
        /// <param name="requestUri"></param>
        /// <param name="dic">
        /// Contains at least sessionId after suceessful login to the SF org
        /// </param>
        /// <param name="method">One of the standard HTTP methods</param>
        /// <param name="content">holds the possible form-like content (JSON) serialized as a string</param>
        /// <returns>ResponseMessage (null) in case of failure -- errors go to the log</returns>
        private static async Task<HttpResponseMessage> ReadFromSalesForce(Uri requestUri, 
            IDictionary<string,string> dic, HttpMethod method, string content = null, string accepts = "application/json")
        {
            HttpResponseMessage response = new HttpResponseMessage();
            HttpRequestMessage msg = new HttpRequestMessage
            {
                Method = method,
                RequestUri = requestUri,
                Headers = {
                    { HttpRequestHeader.Accept.ToString(), accepts },
                    { "Authorization", "Bearer " + dic["sessionId"] }
                }
            };
            if (content != null)
            {
                msg.Headers.Add(HttpRequestHeader.ContentType.ToString(), "application/json");
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
        /// <summary>
        /// Helper method to wait wt seconds for the user interactions
        /// </summary>
        /// <param name="wt"></param>
        private static void WaitExitingCountdown(TimeSpan wt)
        {
            int i = wt.Seconds;
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
            HelpText ="Set the working mode.\nRead - to read the data from the SF org and store them into a file (filer can be applied);" +
            "\nWrite - to read the data from encrypted file and store them back into the SF org;"+
            "\nCompare - to compare the data from the encrypted file and SF org;" +
            "\nPrepare - to prepare Crypto stuff in the given KDBX file (adds correctly filled AESPassword, Salt and IV records)" +
            "\nSubset - to store a subset in the RDB (filter can be applied)")]

        public WorkingModes WorkMode { get; set; }

        [Option('d', "salesforcedomain",
            Default = "test", MetaValue = "test",
            HelpText = "Represents a domain used to log into SalesForce from, e.g. https://test.salesforce.com")]
        public string SalesForceDomain { get; set; }

        [Option('g', "groupname", Required = true, MetaValue ="EPAM",
            HelpText = "Gives the name of the group in the KeePass file where to look for the entry with SalesForce credentials")]
        public string GroupName { get; set; }

        [Option('e', "entryname", Required = true, MetaValue = "EPAM",
            HelpText = "Gives the name of the Entry within the group in the KeePass file with necessary credentials to connect to the SalesForce org")]
        public string EntryName { get; set; }

        [Option('k', "kdbxpath", Required = true,
            HelpText = "Sets the path to the KeePass file with the credentials. The file must not be key-file protected!")]
        public string KDBXPath { get; set; }

        [Option('o', "sfobject", Default = SFObjectsWithAttachments.Document,
            HelpText ="Points out which SalesForce object the body of attachments should be taken from",
            MetaValue ="Document")]
        public SFObjectsWithAttachments SFObject { get; set; }

        [Option('t',"targetfile",
            HelpText = "Sets the path to the target (source in case of write) file to store (to read) encrypted attachments to (from)")]
        public string EcryptedAttachmentsTargetFile { get; set; }

        [Option('n',"threads", Default = 2, MetaValue ="2",
            HelpText = "Sets the number of concurrent threads")]
        public int NumberOfWorkingThreads { get; set; }

        [Option ('c', "comppath",
            HelpText ="Sets path to the file with comparison results" +
            "\nIn case Subset workmode is selected and files are going to be stored in a CSV format sets a target folder",
            MetaValue = "D:\\Doc_comp_res.dat")]
        public string ComparisonResultsFilePath { get; set; }

        [Option('l', "logfile",
            HelpText ="Sets the path to the logging file in additon to logging to the Console")]
        public string LogFilePath { get; set; }

        [Option('x',"logtoconsole", Default = 1,
            HelpText ="Switches logging to Console mode on(<>0)/off(0). Might be useful since it doesn't waste time on UI output, though makes survey possible only through log file (if any provided).",
            MetaValue = "1")]
        public int LogToConsole { get; set; }

        [Option('f',"filter", Default = null,
            HelpText ="Takes a filter when running in the \"Read\" mode; \nWHERE keyword must be omitted;" +
            "\ntext values must be enclosed in the single quotes." +
            "\nTo select necesssary objects when creating a Subset give pipe-separated list of object names",
            MetaValue = "Id IN ('Id1', 'Id2')")]
        public string ReadModeFilter { get; set; }

        [Option('w', Default = 0,
            HelpText ="If this parameter is set to any value different from 0 then access to the KeePass file will be done using the current windows logon",
            MetaValue = "0")]
        public int UseWindowsAccount { get; set; }
    }

    enum SFObjectsWithAttachments
    {
        Attachment,
        Document
    }

    enum WorkingModes
    {
        Read,       //Reads attachments from the selected (default) object in the SF org and stores its encrypted copies into the given (or default) CSV file
        Write,      //Writes the content of the encrypted copies of attachment in the selected (default) object to the given SF org
        Compare,    //Compares attachments in the selected (default) object of the SF org with their encypted copies and stores comaprison results into the given (default) file
        Prepare,    //Prepares the cryptographic stuff in the given KeePass entity/group necessary to perform the above operations
        Subset      //Create a subset of the objects in the given SalesForce org filter in this case must be pipe-separated object names
    }

    enum ExitCodes
    {
        ArgumentParsingError = -1,
        CryptographicStuffAbsenseError = -2,
        GettingSalesForceSessionIDError = -3,
        ComparisonFileIsAbsentError = -4,
        UnknownError = -999
    }
}