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
using System.Web;
using Oracle.ManagedDataAccess.Client;
using CsvHelper;
using CsvHelper.Configuration;
using System.Globalization;
using System.Data;
using System.Reflection;

namespace SalesForceAttachmentsBackupTools
{
    class AttachmentsBackup
    {
        #region fields
        private static string pathToKeePassDb;
        private static string groupName;
        private static string entryName;
        private static string ORCLgroupName;
        private static string ORCLentryName;
        private static string domainName;
        private static string objectWithAttachments;
        private static string resultFileName;
        private static string pathToComparisonResults;
        private static string filter;
        private static string pathToJSONfile;
        private static string prefix;
        private static string pathToIDs;                            //Path to the CSV file with IDs to be restored in the write mode
        private static int numberOfRows;                            //Sets the number of rows one part of the back-up file could contain
        private static int numberOfThreads;                         //Sets the number of workers simultaneously executing the Job
        private static int numberOfRetries = 3;                     //Hardcoded number of retries for push
        private static int pushTimeOut;                             //Initial timeout for the bulk packages pushed to the ORACLE instance
        private static int minNumberOfRecords = int.MaxValue;       //Minimal number of records when subset cannot be done
        private static int percentForSubset = 100;                  //Percent of original data to be passed to the subset
        private static int bulkQueryLengthLimit = 100000;           //The limit imposed by the SalesForce on the bulk query length
        private static int delayBetweenIDSkips = 50;                //The delay in milliseconds between thread skipping the row in the write mode and take an ID
                                                                    //Needed to be introduced since the consuming threads do devour rows too fast when skipping 
        private static HttpClient client = new HttpClient() { Timeout = Timeout.InfiniteTimeSpan};
        private static ConsoleKeyInfo key;
        private static WorkingModes workingMode;
        private static List<string> listOfIds = null;               //Either list of Ids for Read, Write and Compare mode or list of SF Objects
        private static JToken listOfNonSensitivePairs = null;                                  //list of object-field pairs that schould not come into copy
        private static MinSizeQueue<KeyValuePair<string, string>> minSizeQueue;                 //A queue of Id and Base64-encoded binary attachment to process by the workers
        private static TimeSpan waittime = TimeSpan.FromSeconds(30);                            //Time to wait before console closure
        private static ConsoleTraceListener consoleTraceListener = new ConsoleTraceListener();
        private static bool useWindowsLogon = false;                                            //Use windows authentication to open KBDX
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
                    if (opt.RetriesNumber >= 0 && opt.RetriesNumber <= 10) numberOfRetries = opt.RetriesNumber;
                    pushTimeOut = 0;// opt.PushTimeout;
                    domainName = opt.SalesForceDomain;
                    groupName = opt.GroupName;
                    entryName = opt.EntryName;
                    pathToKeePassDb = opt.KDBXPath;
                    objectWithAttachments = Enum.GetName(typeof(SFObjectsWithAttachments), opt.SFObject);
                    resultFileName = opt.EcryptedAttachmentsTargetFile ?? "encrypted_" + objectWithAttachments + ".dat";
                    workingMode = opt.WorkMode;
                    numberOfThreads = opt.NumberOfWorkingThreads;
                    useWindowsLogon = opt.UseWindowsAccount == 1;
                    pathToJSONfile = opt.PathToExcludeObjectsJson;
                    pathToIDs = opt.PathToWriteIDs;
                    if (opt.LogFilePath != null && !opt.LogFilePath.Equals(String.Empty))
                    {
                        Trace.Listeners.Add(new TextWriterTraceListener(opt.LogFilePath, "Backup_fileTracer"));
                        Trace.Listeners["Backup_fileTracer"].TraceOutputOptions |= TraceOptions.DateTime;
                    }
                    if (opt.LogToConsole != 0)
                    {
                        consoleTraceListener.TraceOutputOptions = TraceOptions.DateTime;
                        Trace.Listeners.Add(consoleTraceListener);
                    }
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
                            if (opt.MaxRowsInAPart <=0)
                            {
                                numberOfRows = int.MaxValue;
                            }
                            else
                            {
                                numberOfRows = opt.MaxRowsInAPart;
                            }
                            if (!string.IsNullOrEmpty(opt.ReadModeFilter))
                            {
                                filter = HttpUtility.UrlEncode(" WHERE " + opt.ReadModeFilter, Encoding.ASCII);
                            }
                        }
                        if (workingMode == WorkingModes.Subset)
                        {
                            if (opt.ORCLEntryName == null || opt.ORCLEntryName.Equals(String.Empty)
                                || opt.ORCLGroupName == null || opt.ORCLGroupName.Equals(String.Empty))
                            {
                                Trace.TraceError($"If workmode is set to Subset then credentials to connect to an Oracle instance must be provided.");
                                WaitExitingCountdown(waittime);
                                Environment.Exit((int)ExitCodes.CredentialsAbsenseError);
                                return 0;
                            }
                            ORCLentryName = opt.ORCLEntryName;
                            ORCLgroupName = opt.ORCLGroupName;
                            filter = opt.ReadModeFilter;
                            if (opt.SubsetNumberOfRecords <= 0 || opt.SubsetPercentage > 100)
                            {
                                Trace.TraceWarning("Percentage range is invalid; using default value");
                            }
                            else percentForSubset = opt.SubsetPercentage;
                            if (opt.SubsetNumberOfRecords <= 0) 
                            { 
                                Trace.TraceWarning("Minimal number of recods cannot be negative; using default value"); 
                            }
                            else minNumberOfRecords = opt.SubsetNumberOfRecords;
                            
                        }
                    }
                    Trace.TraceInformation("Arguments have been successfully parsed");
                    return 1;
                },
                (IEnumerable<Error> errs) =>
                {
                    //Let the user read the error message and exit after waittime expires
                    WaitExitingCountdown(waittime);
                    Environment.Exit((int)ExitCodes.ArgumentParsingError);
                    return 0;
                });

            AssemblyName name = Assembly.GetExecutingAssembly().GetName();

            Trace.TraceInformation(string.Format("{0} {1:0}.{2:0}.{3:0}.{4:0}",
                "current version",
                name.Version.Major.ToString(),
                name.Version.Minor.ToString(),
                name.Version.Build.ToString(),
                name.Version.Revision.ToString()
                ));

            //Open KeePass (needed for every operation) and store credentials in the dictionary
            //This is done with regard that the KDBX file could be protected by Windows credentials
            //starting from some new versions as well.
            SecureString secString = new SecureString();
            if (!useWindowsLogon) secString = ReadPasswordFromConsole();
            credentialsDict = new Dictionary<string, ProtectedString>(OpenKeePassDB(
                    secString, pathToKeePassDb, groupName, entryName, useWindowsLogon));
            Trace.TraceInformation($"Got {credentialsDict.Count} credentials");

            //Check whether the number of credentials and their names are enough depending on the workmode
            switch (workingMode)
            {
                case WorkingModes.Read:
                case WorkingModes.Write:
                case WorkingModes.Compare:
                    if (credentialsDict.Where(t => t.Key == "IV" || t.Key == "AESPass" || t.Key == "Salt").Count() < 3)
                    {
                        Trace.TraceError("Insufficient cryptographic stuff; Either IV, Password for encryption or Salt records are absent in the given group/entity");
                        WaitExitingCountdown(waittime);
                        Environment.Exit((int)ExitCodes.CryptographicStuffAbsenseError);
                        return;
                    }
                    else if(credentialsDict.Where(t => t.Key == "UserName" || t.Key == "Password").Count() < 2)
                    {
                        Trace.TraceError("Either Password or UserName are absent in the given group/entity");
                        WaitExitingCountdown(waittime);
                        Environment.Exit((int)ExitCodes.CredentialsAbsenseError);
                        return;
                    }
                    Trace.TraceInformation("Credentials and cryptographic stuff seem to be OK");
                    break;
                case WorkingModes.Subset:
                    foreach (KeyValuePair<string, ProtectedString> kv in OpenKeePassDB(
                    secString, pathToKeePassDb, ORCLgroupName, ORCLentryName, useWindowsLogon))
                    {
                        credentialsDict.Add("ORCL" + kv.Key, kv.Value);
                    }

                    if (credentialsDict.Where(t => t.Key.StartsWith("ORCL")).Count() < 3)
                    {
                        Trace.TraceError("Not enough credentials to work in Subset mode. Oracle credentials weren't found in the KDBX.");
                        WaitExitingCountdown(waittime);
                        Environment.Exit((int)ExitCodes.CredentialsAbsenseError);
                    }
                    else
                    {
                        Trace.TraceInformation("Got 3 supplementary credentials to connect to an Oracle instance");
                    }

                    if (credentialsDict.Where(t => t.Key == "UserName" || t.Key == "Password").Count() < 2)
                    {
                        Trace.TraceError("Either Password or UserName are absent in the given group/entity");
                        WaitExitingCountdown(waittime);
                        Environment.Exit((int)ExitCodes.CredentialsAbsenseError);
                        return;
                    }
                    Trace.TraceInformation("Credentials and cryptographic stuff seem to be OK");
                    break;
                default:
                    break;
            }

            //Connect to the SalesForce org and store the results in a dictionary
            Dictionary<string, string> salesForceSID = new Dictionary<string, string>(await GetSalesForceSessionId(credentialsDict));
            if (salesForceSID.Count == 0)
            {
                Trace.TraceError("Error getting SalesForce session ID. Exiting...");
                WaitExitingCountdown(waittime);
                Environment.Exit((int)ExitCodes.GettingSalesForceSessionIDError);
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
                        Environment.Exit((int)ExitCodes.NothingToReadError);
                    }
                    break;
                case WorkingModes.Write:
                case WorkingModes.Compare:
                    if (!File.Exists(resultFileName))
                    {
                        Trace.TraceError("Source file does not exist. Exiting...");
                        WaitExitingCountdown(waittime);
                        Environment.Exit((int)ExitCodes.SourceFileDoesNorExistsError);
                    }
                    break;
                case WorkingModes.Subset:
                    listOfIds = new List<string>();
                    prefix = GeneratePrefix(5);
                    using (OracleConnection con = new OracleConnection())
                    {
                        try
                        {
                            con.ConnectionString = $"User ID={credentialsDict["ORCLUserName"].ReadString()}; " +
                            $"Password={credentialsDict["ORCLPassword"].ReadString()}; " +
                            $"Data Source={credentialsDict["ORCLDataSource"].ReadString()};";
                            con.Open();
                            OracleCommand cmd = new OracleCommand("SELECT 1 FROM DUAL", con);
                            cmd.ExecuteScalar();

                            //The Oracle command executed OK therefore the Connection String could be passed as a Protected string in a dictionary
                            credentialsDict.Add("ORCLConnectionString", 
                                new ProtectedString(true, $"User ID={credentialsDict["ORCLUserName"].ReadString()}; " +
                                $"Password={credentialsDict["ORCLPassword"].ReadString()}; " +
                                $"Data Source={credentialsDict["ORCLDataSource"].ReadString()};"));
                            Trace.TraceInformation("Target DB connection OK");
                        }
                        catch
                        {
                            Trace.TraceError($"Error opening ORACLE connection. Exiting...");
                            WaitExitingCountdown(waittime);
                            Environment.Exit((int)ExitCodes.TargetDBConnectionError);
                        }
                        finally
                        {
                            con.Close();
                        }
                    }
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
                    //Save the initial number of rows queued for backing-up for further comparison
                    //it may increase due to read errors and re-enqueuing
                    {
                        List<Task<int>> tasks_int = new List<Task<int>>();
                        int initialNumberOfRows = listOfIds.Count;
                        //Holds the number of the rows actually written to the back-up files for the further comaprison
                        int numberOfBackedRows = 0;
                        using (PartialStreamWriter resultStream = new PartialStreamWriter(numberOfRows, resultFileName, false, Encoding.ASCII))
                        {
                            resultStream.NewPartStarted += delegate (object sender, NewPartStartedEventArgs e)
                            {
                                Trace.TraceInformation($"New part has been started {e.newPartPath}");
                            };
                            Trace.TraceInformation($"Initiating {numberOfThreads} workers to read data.");
                            for (int i = 0; i < numberOfThreads; i++)
                            {
                                tasks_int.Add(Task<int>.Run(
                                    () => doWork(listOfIds.ToList(), salesForceSID, objectWithAttachments,
                                        cipher.CreateEncryptor(Convert.FromBase64String(credentialsDict["pwdKey"].ReadString()), cipher.IV), resultStream)));
                            }
                            Task<int>.WaitAll(tasks_int.ToArray());
                            //Count the number of actually added (backed) rows
                            tasks_int.ToList<Task<int>>().ForEach(t => numberOfBackedRows += t.Result);
                            Trace.TraceInformation($"Planned to back-up {initialNumberOfRows} rows, actually backed {numberOfBackedRows} rows; " +
                                $"{((initialNumberOfRows==numberOfBackedRows)?"the object has been fully backed.":"back-up is not full, please consider revision.")}");
                        }
                        break;
                    }
                case WorkingModes.Write:
                    minSizeQueue = new MinSizeQueue<KeyValuePair<string, string>>(numberOfThreads);
                    
                    //A block just to make the variables local
                    {
                        Regex reg = new Regex(@"^[a-zA-Z\d]{18}");
                        List<string> idsToRestore = new List<string>();

                        //Process the list of IDs to be restore if any is given
                        if (!String.IsNullOrEmpty(pathToIDs) && File.Exists(pathToIDs))
                        {
                            Trace.TraceInformation($"The list of IDs has been provided in the {pathToIDs}; analyzing...");
                            try
                            {
                                using (StreamReader reader = new StreamReader(pathToIDs, Encoding.ASCII))
                                using (CsvReader csv = new CsvReader(reader,
                                    new CsvConfiguration(CultureInfo.InvariantCulture) { NewLine = "\r\n" }))
                                {
                                    csv.Read();
                                    if (csv.ReadHeader())
                                    {
                                        if (csv.HeaderRecord.Length > 0 && csv.HeaderRecord.Any(t => t.Equals("id", StringComparison.InvariantCultureIgnoreCase)))
                                        {
                                            int index = Array.FindIndex<string>(csv.HeaderRecord, t => t.Equals("id", StringComparison.InvariantCultureIgnoreCase));
                                            while (csv.Read())
                                            {
                                                string record = new String(csv.GetField<string>(index).ToArray<char>());
                                                if (reg.Match(record).Captures.Count == 1)
                                                {
                                                    idsToRestore.Add(record);
                                                }
                                                else
                                                {
                                                    Trace.TraceWarning($"Invalid SalesForce Id {record} has been provided for Write filter, skipping...");
                                                }
                                            }
                                        }
                                        else
                                        {
                                            Trace.TraceError("The provided file with IDs list is OK but no \"id\" column has been found.");
                                            WaitExitingCountdown(waittime);
                                            Environment.Exit((int)ExitCodes.IDFileWrongFormatError);
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Trace.TraceError("Error opening file with Ids for write mode."
#if TRACE
                                    + $"\n{ex.Message}"
#endif
                                    );
                                WaitExitingCountdown(waittime);
                                Environment.Exit((int)ExitCodes.OpenIDFileError);
                            }
                            Trace.TraceInformation($"{idsToRestore.Count} IDs have been ordered for restoration");
                        }
                        else
                        {
                            Trace.TraceWarning("No IDs filtering is provided, proceeding with all the backed values");
                        }

                        Queue<string> backupFiles = new Queue<string>(new string[] { resultFileName });

                        Directory.GetFiles(Path.GetDirectoryName(resultFileName), Path.GetFileName(resultFileName) + ".part????")
                            .ToList<string>().ForEach(t =>
                            {
                                backupFiles.Enqueue(t);
                                Trace.TraceInformation($"A part {t} has been found. Adding to the queue");
                            }
                            );
                        string currentBackupFile;
                        while (backupFiles.Count > 0)
                        {
                            currentBackupFile = backupFiles.Dequeue();
                            Trace.TraceInformation($"Starting to process {currentBackupFile}");
                            _ = FillQueue(currentBackupFile);
                            Trace.TraceInformation($"Initiating {numberOfThreads} workers to write data.");
                            for (int i = 0; i < numberOfThreads; i++)
                            {
                                tasks.Add(Task.Run(
                                    () => doWork(minSizeQueue, salesForceSID, objectWithAttachments, 
                                        cipher.CreateDecryptor(Convert.FromBase64String(credentialsDict["pwdKey"].ReadString()), cipher.IV),
                                        idsToRestore)));
                            }
                            Task.WaitAll(tasks.ToArray());
                        }
                    }
                    break;
                case WorkingModes.Compare:
                    minSizeQueue = new MinSizeQueue<KeyValuePair<string, string>>(numberOfThreads);
                    
                    //A block just to make variables local
                    {
                        Queue<string> backupFiles = new Queue<string>(new string[] { resultFileName });

                        Directory.GetFiles(Path.GetDirectoryName(resultFileName), Path.GetFileName(resultFileName) + ".part????")
                            .ToList<string>().ForEach(t => 
                                {
                                    backupFiles.Enqueue(t);
                                    Trace.TraceInformation($"A part {t} has been found. Adding to the queue");
                                }
                            );
                        string currentBackupFile;
                        bool append = false;
                        while (backupFiles.Count > 0)
                        {
                            currentBackupFile = backupFiles.Dequeue();
                            Trace.TraceInformation($"Starting to process {currentBackupFile}");
                            _ = FillQueue(currentBackupFile);
                            using (TextWriter resultStream = TextWriter.Synchronized(new StreamWriter(pathToComparisonResults, append, Encoding.ASCII)))
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
                            append = true;
                        }
                    }
                    break;
                case WorkingModes.Subset:
                    if (pathToJSONfile != null && !pathToJSONfile.Equals(String.Empty)) 
                    { 
                        salesForceSID.Add("pathToJson", pathToJSONfile); 
                    }
                    else
                    {
                        salesForceSID.Add("pathToJson", Path.Combine(Directory.GetCurrentDirectory(), "ObjectsToExclude.json"));
                    }

                    //A Tuple is used to work-around the impossibility to have out parameters in the async methods
                    Tuple<IEnumerable<string>, JToken> jsonParseResult = await GetListOfObjects(salesForceSID, filter);
                    if(jsonParseResult.Item2 == null)
                    {
                        Trace.TraceError("No nonsensitive pairs were returned from the given path.");
                        WaitExitingCountdown(waittime);
                        Environment.Exit((int)ExitCodes.ObjectListError);
                    }
                    listOfIds = jsonParseResult.Item1.ToList<string>();
                    listOfNonSensitivePairs = jsonParseResult.Item2;
                    List<Task> uploadTasks = new List<Task>();

                    //Add prefix to the dictionary
                    salesForceSID.Add("prefix", prefix);

                    Trace.TraceInformation($"Initiating {numberOfThreads} workers to create a representative subsets of the data.");
                    Trace.TraceInformation($"Prefix for the tables is {prefix}");

                    //Pass a new list to each thread to get the files that need to be cleared up
                    ConcurrentList<string> cleanUpList = new ConcurrentList<string>(numberOfThreads * 2);
                    for (int i = 0; i < numberOfThreads; i++)
                    {
                        tasks.Add(Task.Run(
                            () => doWork(listOfIds, salesForceSID, credentialsDict.Where(k => k.Key.Equals("ORCLConnectionString"))
                                .ToDictionary(k=>k.Key, k=>k.Value),
                            listOfNonSensitivePairs, uploadTasks)));
                    }
                    Task.WaitAll(tasks.ToArray());
                    Trace.TraceInformation($"Wating for {uploadTasks.Count(t => (!t.IsCompleted && !t.IsFaulted && !t.IsFaulted))} upload tasks to finish");
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
        private static async Task<Tuple<IEnumerable<string>, JToken>> GetListOfObjects(IDictionary<string, string> dic, string flt)
        {
            IEnumerable<JToken> excludeArray;
            JArray arr;
            Trace.TraceInformation("Getting the list of the objects, please, wait it may take a little while...");
            HttpResponseMessage listOfObjects = await ReadFromSalesForce(new Uri(dic["serverUrl"] + "/sobjects/"), 
                dic, HttpMethod.Get, null);
            if (listOfObjects.Content != null)
            {
                arr = JArray.Parse(JObject.Parse(await listOfObjects?.Content?.ReadAsStringAsync())["sobjects"].ToString());
                Trace.TraceInformation($"Got totally {arr.Count} objects");
                Trace.TraceInformation($"Amongst them only {arr.Where(t => t["updateable"].ToString().Equals("True")).Count()} are updatable");

                //Compose an array to be used for exclusion of __Share objects since they cannot contain any sensitive information
                excludeArray = arr.Where(t => t["name"].ToString().EndsWith("__Share"));
                excludeArray = excludeArray.Concat(arr.Where(t => t["name"].ToString().EndsWith("__Tag")));
            }
            else
            {
                Trace.TraceError($"Error getting list of objects. Exiting...");
                return new Tuple<IEnumerable<string>, JToken>(new string[1], JToken.Parse("{}"));
            }
            JObject data = null;
            // Others exclusions must be added in the same manner here
            string path;
            if (dic.TryGetValue("pathToJson", out path))
            {
                try
                {
                    data = JObject.Parse(File.ReadAllText(path));
                    excludeArray = excludeArray.Concat(JArray.Parse(data["ObjectsToExclude"].ToString()).Intersect(arr).ToList());
                }
                catch
                {
                    Trace.TraceWarning("Wrong path to the JSON file is given!");
                }
            }
 
            List<string> lst = new List<string>();
            if (flt == null)
            {
                Trace.TraceInformation("No filter is given adding all the possible objects to the list");

                lst = arr.Where(t => t["updateable"].ToString().Equals("True"))
                            .Except(excludeArray)
                            .Select(j => j["name"].ToString()).ToList<string>();
            }
            else
            {
                lst = arr.Where(t => t["updateable"].ToString().Equals("True"))
                        .Except(excludeArray)
                        .Join(filter.Split('|'),
                            p => p["name"].ToString(),
                            t => t,
                            (p, t) => t)
                        .Select(t => t).ToList<string>();
            }
            Trace.TraceInformation($"Total number of objects to be processes is {lst.Count}");
            return new Tuple<IEnumerable<string>, JToken>(lst, data?["FieldsToExclude"]);
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
                requestUri = new Uri(dic["serverUrl"] + "/query/?q=SELECT+Id+FROM+" + obj + filter + "+ORDER+BY+Id+ASC+NULLS+LAST");
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
        /// <param name="creds">credentials to connect to the salesforce org etc</param>
        /// <param name="ORCLcreds">credentials to connect to the oracle instance</param>
        /// <param name="excludeFields">JSON with the list of Object:Field values to be excluded from the subsetting</param>
        /// <param name="uploadTasks">the list of tasks started to upload the sensitive data in the RDB to be waited on after the worker thread has finished</param>
        /// <returns></returns>
        private static async Task doWork(ICollection<string> listOfIds, IDictionary<string, string> creds, IDictionary<string
            , ProtectedString> ORCLcreds, JToken excludeFields, List<Task> uploadTasks)
        {
            SynchronizedIds psid = new SynchronizedIds();
            int currentId, initialSleep, numberOfRecords;
            List<string> mixedIds = new List<string>();
            bool needsToSubset;
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            HttpResponseMessage resp = null;
            StringBuilder createSQL = new StringBuilder();
            string prfx;

            if (!creds.TryGetValue("prefix", out prfx)) prfx = "ABCDE";

            //A loop till the queue with objects is not empty
            do
            {
                //Initialize variables for each object
                initialSleep = 3;
                numberOfRecords = int.MaxValue;
                currentId = psid.GetCurrentID();
                mixedIds.Clear();
                needsToSubset = false;
                createSQL.Clear();
                Task ORCLTask = null;

                if (listOfIds.Count(k => k != null) > 0 && currentId < listOfIds.Count && !(listOfIds.ToList())[currentId].Equals(string.Empty))
                {
                    string currObject = (listOfIds.ToList())[currentId];
                    string tableName = ComposeTableName(currObject, guid, prfx);
                    createSQL.Append($"CREATE TABLE {tableName} (Id VARCHAR2(18) NOT NULL");
                    
                    //Getting number of records in the current object
                    try
                    {
                        Trace.TraceInformation($"Thread {guid} is sending request to get the number of records in the {currObject}");
                        resp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/query/?q=" + 
                            HttpUtility.UrlEncode($"SELECT count(Id) FROM {currObject}", Encoding.ASCII)), creds, HttpMethod.Get, null);
                        if (resp != null && resp.Content != null && resp.StatusCode == HttpStatusCode.OK)
                        {
                            if (Int32.TryParse(JObject.Parse(await resp.Content.ReadAsStringAsync())["records"][0]["expr0"].ToString()
                                , out numberOfRecords)) 
                            {
                                Trace.TraceInformation($"Thread {guid} has defined that the number of records in the {currObject} is {numberOfRecords}");
                                if (numberOfRecords == 0)
                                {
                                    Trace.TraceInformation($"Thread {guid} has defined that the object {currObject} is empty." +
                                        $" Nothing to store in DB");
                                    continue;
                                }
                            }
                            else
                            {
                                Trace.TraceError($"Thread {guid} has caught an error getting nunber of records from the {currObject} " +
                                    $"\nWill proceed anyway assuming the number if infinite");
                                numberOfRecords = int.MaxValue;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Trace.TraceWarning($"Thread {guid} has caught an error while reading number of lines for the {currObject}: {ex.Message}");
                        Trace.TraceWarning($"Thread {guid} decided that No subsetting will be done for the {currObject}");
                    }

                    //Determine if the subsetting of the object needs to be performed
                    if (numberOfRecords >= minNumberOfRecords || percentForSubset < 100)
                    {
                        needsToSubset = true;
                        var jsonObj = new
                        {
                            operation = "query",
                            query = $"SELECT Id FROM {currObject}",
                            contentType = "CSV",
                            columnDelimiter = "PIPE",
                            lineEnding = "CRLF"
                        };
                        try
                        {
                            Trace.TraceInformation($"Thread {guid} is sending request to SF org to get Ids of the {currObject} object");
                            HttpResponseMessage idjobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query")
                                , creds, HttpMethod.Post, JsonConvert.SerializeObject(jsonObj));
                            if (idjobresp != null && idjobresp.Content != null && idjobresp.StatusCode == HttpStatusCode.OK)
                            {
                                JObject jobInfo = JObject.Parse(await idjobresp.Content.ReadAsStringAsync());
                                Trace.TraceInformation($"Thread {guid} has queued a job {jobInfo["id"]} to get the Ids from the {currObject} object");
                                
                                //Loop to wait till the job has completed (or failed)
                                while (jobInfo["state"].ToString().Equals("InProgress") || jobInfo["state"].ToString().Equals("UploadComplete"))
                                {
                                    //Every time the loop will wait twice as longer as the previous time
                                    initialSleep = (int)(initialSleep * 1.5);
                                    Trace.TraceInformation($"Thread {guid} is sleeping for {initialSleep} seconds then will check results...");
                                    Thread.Sleep(initialSleep * 1000);

                                    //Requests for job completion or failure
                                    idjobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query/" + jobInfo["id"])
                                        , creds, HttpMethod.Get);
                                    if (idjobresp != null && idjobresp.Content != null && idjobresp.StatusCode == HttpStatusCode.OK)
                                    {
                                        jobInfo = JObject.Parse(await idjobresp.Content.ReadAsStringAsync());
                                    }
                                    else
                                    {
                                        jobInfo["state"] = "UnknowError";
                                        break;
                                    }
                                }
                                if (jobInfo["state"].ToString().Equals("JobComplete"))
                                {
                                    string locator = string.Empty;
                                    int idBatchNumber = 1;

                                    do
                                    {
                                        //The job has successfully completed. Need to read the CSV data
                                        if (locator.Equals(string.Empty))
                                        {
                                            idjobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query/" + jobInfo["id"]
                                                + "/results?maxRecords=200000")
                                                , creds, HttpMethod.Get, accepts: "txt/csv");
                                        }
                                        else
                                        {
                                            idjobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query/" + jobInfo["id"]
                                                + "/results?locator=" + locator + "&maxRecords=200000")
                                            , creds, HttpMethod.Get, accepts: "txt/csv");
                                        }

                                        Trace.TraceInformation($"Thread {guid} is getting the batch #{idBatchNumber} of Ids for {currObject}");

                                        locator = idjobresp.Headers.GetValues("Sforce-Locator").First();
                                        if (locator.Equals("null")) locator = string.Empty;
                                        
                                        using (StreamReader inputStreamReader = new StreamReader(await idjobresp.Content.ReadAsStreamAsync()))
                                        {
                                            using (var csv = new CsvReader(inputStreamReader,
                                                            new CsvConfiguration(CultureInfo.InvariantCulture) { NewLine = "\r\n" }))
                                            using (var dr = new CsvDataReader(csv))
                                            {
                                                DataTable dt = new DataTable();
                                                dt.Load(dr);
                                                foreach(DataRow d in dt.Rows)
                                                {
                                                    mixedIds.Add(d.ItemArray[0].ToString());
                                                }
                                            }
                                        }
                                        idBatchNumber++;
                                    } while (!locator.Equals(string.Empty));

                                    mixedIds = SubsetHelper<string>.MakeSubset(mixedIds,
                                            SubsetPercentage: percentForSubset, MinNumber: minNumberOfRecords).ToList<string>();
                                    Trace.TraceInformation($"Thread {guid} has mixed up {mixedIds.Count} IDs for the {currObject} object");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Trace.TraceError($"Thread {guid} has caught an exception while trying to get Ids from the {currObject}.\n" +
                            ex.Message);
                        }
                    }
                    else
                    {
                        Trace.TraceInformation($"Thread {guid} has defined that no subsetting is necessary for the {currObject}");
                    }

                    //Getting the description of the current object
                    try
                    {
                        Trace.TraceInformation($"Thread {guid} is sending request to SF org to get the description of the {currObject}");
                        resp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" +currObject + "/describe")
                            , creds, HttpMethod.Get, null);
                    }
                    catch (Exception ex)
                    {
                        Trace.TraceError($"Thread {guid} has caught an exception while working in the subset mode.\n" +
                            ex.Message);
                    }

                    initialSleep = 3;
                    if (resp != null && resp.Content != null && resp.StatusCode == HttpStatusCode.OK)
                    {
                        JArray arrFields = JArray.Parse(JObject.Parse(await resp.Content.ReadAsStringAsync())["fields"].ToString());
                        Trace.TraceInformation($"Thread {guid} has got {arrFields.Count} fields described in the {currObject}");

                        //If the the subsetting is required then create a partial request since its length cannot be more than 100000 characters
                        //And there is no way to select random IDs except by naming them in the query -- no more than 4750 'Ids'
                        int indexOfId = 0;
                        int runNumber = 0;
                        List<Task> idJobs = new List<Task>();
                        CancellationTokenSource source = new CancellationTokenSource();
                        //will throttle the number of simultaneously running push tasks
                        Semaphore slim = new Semaphore(3, 3, "semaphore_" + guid.ToString("N"));
                        //For every batch (run)
                        do {
                            bool commaFlag = false;
                            StringBuilder limitedWhereCondition = new StringBuilder();
                            StringBuilder fieldsList = new StringBuilder("SELECT Id,"
                                + arrFields.Where(t => t["updateable"].ToString().Equals("True")
                                        && !t["type"].ToString().Equals("boolean")
                                        && !t["type"].ToString().Equals("picklist")
                                        && !t["type"].ToString().Equals("reference")
                                        && !t["type"].ToString().Equals("double"))
                                //.Take(200)
                                    .Select(o => o["name"].ToString())
                                    //Exclude the non-sensitive fileds pecific to the current Object
                                    .Except((excludeFields ?? JToken.Parse("{}"))
                                        .Select(t => t[currObject]?.ToString())
                                        .Where(t => t != null)
                                        //Exclude the non-sensitive fields common to all Objects
                                        .Concat((excludeFields ?? JToken.Parse("{}"))
                                        .Select(t => t["AnyObject"]?.ToString())
                                        .Where(t => t != null))
                                        )
                                    .Aggregate("", (c, n) => $"{c},{n}")
                                    .TrimStart(',')
                                    + " FROM " + currObject);
                            if (needsToSubset)
                            {
                                //define the length of its variable fields parts
                                limitedWhereCondition.Append(" WHERE Id IN(");
                                int initialQueryLength = fieldsList.Length + limitedWhereCondition.Length;
                                //append to the WHERE condition as long as there are enough Ids or the length treshold is not overcome
                                while (initialQueryLength + limitedWhereCondition.Length 
                                    //21 is the length of the quoted Id plus comma
                                    //but API gives an error stating it is 73 bytes longer than allowed
                                    //obviously they count other parts of the JSON as the query hence addiotional 100 bytes
                                    + 121 
                                    < bulkQueryLengthLimit && indexOfId < mixedIds.Count)
                                {
                                    limitedWhereCondition.Append((commaFlag ? ",'" : "'") + mixedIds[indexOfId++] + "'");
                                    commaFlag = true;
                                }
                                limitedWhereCondition.Append(")");
                                runNumber++;
                                Trace.TraceInformation($"Thread {guid} is preparing a query for the run #{runNumber}");
                                initialSleep = 3;
                            }

                            var jobJsonObj = new
                            {
                                operation = "query",
                                query = fieldsList.ToString()
                                    //If needs to subset then add WHERE IN condition
                                    + limitedWhereCondition.ToString(),
                                contentType = "CSV",
                                columnDelimiter = "PIPE",
                                lineEnding = "CRLF"
                            };

                            //Run table creation task in an async mode with no await only in the first batch
                            if (runNumber <= 1)
                            {
                                //Continue to compose a SQL query to create a table
                                foreach (string s in arrFields.Where(t => t["updateable"].ToString().Equals("True") 
                                        && !t["type"].ToString().Equals("boolean")
                                        && !t["type"].ToString().Equals("picklist")
                                        && !t["type"].ToString().Equals("reference")
                                        && !t["type"].ToString().Equals("double"))
                                    //.Take(200)
                                        .Select(o => o["name"].ToString())
                                        .Except((excludeFields ?? JToken.Parse("{}"))
                                                //Exclude the non-sensitive fields for the specific Object
                                                .Select(t => t[currObject]?.ToString())
                                                .Where(t => t != null)
                                                //Exclude the non-sensitive fields common to all and Objects
                                                .Concat((excludeFields ?? JToken.Parse("{}"))
                                                .Select(t => t["AnyObject"]?.ToString())
                                                .Where(t => t != null))
                                            )
                                        )
                                {
                                    createSQL.Append($",\"{s.ToUpper()}\" VARCHAR2(4000)");
                                }
                                createSQL.Append(")");

                                Trace.TraceInformation($"Thread {guid} creates a table in the Oracle instance to hold the data of the {currObject}");
                                ORCLTask = Task.Run(() =>
                                {
                                    using (OracleConnection oc = new OracleConnection())
                                    {
                                        oc.ConnectionString = $"{ORCLcreds["ORCLConnectionString"].ReadString()}";
                                        oc.Open();
                                        OracleCommand ocmd = new OracleCommand(createSQL.ToString(), oc);
                                        ocmd.ExecuteNonQuery();
                                        //Add a comment to the table where to define the current object
                                        //and designated worker that created it and the timestamp
                                        ocmd.CommandText = $"COMMENT ON TABLE {tableName} IS " +
                                            $"'{currObject} created by the worker {guid} at {String.Format("{0:O}", DateTime.Now)}'";
                                        ocmd.ExecuteNonQuery();
                                        oc.Close();
                                    }
                                });
                                Trace.TraceInformation($"Thread {guid} is waiting for {ORCLTask?.Id} to complete DDL for the {currObject}");
                                ORCLTask?.Wait();
                                if (ORCLTask?.Status != TaskStatus.RanToCompletion)
                                {
                                    Trace.TraceError($"Thread {guid}: DDL creation task {ORCLTask?.Id} for the {currObject} has failed. Data are dropped");
                                    //Stop dealing with the object
                                    break;
                                }
                            }

                            DataTable bulkData = new DataTable();

                            //Run the process getting the data in a separate thread
                            idJobs.Add(Task.Run(async () =>                                {
                                int iniSleep = 3;
                                int rnNumber = runNumber;
                                HttpResponseMessage jobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query")
                                    , creds, HttpMethod.Post, JsonConvert.SerializeObject(jobJsonObj));

                                if (jobresp != null && jobresp.Content != null && jobresp.StatusCode == HttpStatusCode.OK)
                                {
                                    JObject jobInfo = JObject.Parse(await jobresp.Content.ReadAsStringAsync());
                                    Trace.TraceInformation($"Thread {guid} has queued a job {jobInfo["id"]} to get the data from the {currObject} object");

                                    //Loop to wait till the job has completed (or failed)
                                    while (jobInfo["state"].ToString().Equals("InProgress") || jobInfo["state"].ToString().Equals("UploadComplete"))
                                    {
                                        //Every time the loop will wait an half as longer as the previous time
                                        iniSleep = (int)(iniSleep * 1.5);
                                        Trace.TraceInformation($"Thread {guid} is sleeping for {iniSleep} seconds then will check results for the run #{rnNumber}");
                                        Thread.Sleep(iniSleep * 1000);

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
                                        //Set maxRecords parameter to the greater value so as to force SF to compose all smaller batches (?)
                                        //in one batch
                                        jobresp = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/jobs/query/" + jobInfo["id"] + "/results?maxRecords=10000")
                                            , creds, HttpMethod.Get, accepts: "txt/csv");
                                        
                                        try
                                        {
                                            Trace.TraceInformation($"Thread {guid} is pushing the batch #{rnNumber} of the {currObject} to the Oracle instance");
                                            uploadTasks.Add(Task.Run(async () =>
                                            {
                                                slim.WaitOne();
                                                using (OracleConnection con = new OracleConnection())
                                                {
                                                    con.ConnectionString = $"{ORCLcreds["ORCLConnectionString"].ReadString()}";
                                                    con.Open();
                                                    using (StreamReader inputStreamReader = new StreamReader(await jobresp.Content.ReadAsStreamAsync()))
                                                    using (CsvReader csv = new CsvReader(inputStreamReader,
                                                    new CsvConfiguration(CultureInfo.InvariantCulture) { Delimiter = "|", NewLine = "\r\n" }))
                                                    using (CsvDataReader dr = new CsvDataReader(csv))
                                                    {
                                                        DataTable dt = new DataTable();
                                                        dt.Load(dr);
                                                        using (OracleBulkCopy bulkCopy = new OracleBulkCopy(con)
                                                            {
                                                                DestinationTableName = $"{tableName}",
                                                                BulkCopyTimeout = pushTimeOut,
                                                                NotifyAfter = dt.Rows.Count
                                                            })
                                                        {
                                                            //Create column mappings based on their indices
                                                            for (int i = 0; i < dt.Columns.Count; i++)
                                                            {
                                                                bulkCopy.ColumnMappings.Add(i, i);
                                                            }
                                                            
                                                            //Add a notifier event handler 
                                                            bulkCopy.OracleRowsCopied += new OracleRowsCopiedEventHandler(OnRowsCopied);

                                                            //Retries counter
                                                            int k = 0;
                                                            do
                                                            {
                                                                try
                                                                {
                                                                    bulkCopy.WriteToServer(dt);
                                                                    k = numberOfRetries + 1;
                                                                }
                                                                catch (AggregateException aex)
                                                                {
                                                                    if (aex.InnerException is OracleException)
                                                                    {
                                                                        Trace.TraceWarning($"Thread {guid} has exceeded time limit to push batch #{rnNumber} of the {currObject}" +
                                                                            $"\nTrying to push the data once again with the double timeout");
                                                                        bulkCopy.BulkCopyTimeout = pushTimeOut * 3;
                                                                    }
                                                                }
                                                                catch (OracleException oex)
                                                                {
                                                                    Trace.TraceWarning($"Thread {guid} has exceeded time limit to push batch #{rnNumber} of the {currObject}" +
                                                                        $"\nTrying to push the data once again with the tripple timeout");
                                                                    Trace.TraceWarning($"Exception was {oex.Message}");
                                                                    bulkCopy.BulkCopyTimeout = pushTimeOut * 3;
                                                                    k++;
                                                                }
                                                                catch (Exception ex)
                                                                {
                                                                    if (ex.InnerException is OracleException)
                                                                    {
                                                                        Trace.TraceWarning($"Thread {guid} has exceeded time limit to push batch #{rnNumber} of the {currObject}" +
                                                                            $"\nTrying to push the data once again with the tripple timeout");
                                                                        bulkCopy.BulkCopyTimeout = pushTimeOut * 3;
                                                                        k++;
                                                                    }
                                                                    else
                                                                    {
                                                                        Trace.TraceError($"Thread {guid} has caught an Oracle exception the batch #{rnNumber} of the {currObject} has been canceled");
                                                                        Trace.TraceWarning($"\nException was {ex.Message}");
                                                                        k = numberOfRetries + 1;
                                                                    }
                                                                }
                                                            } while (k < numberOfRetries);
                                                            bulkCopy.Close();
                                                        } //Of using bulkcopy

                                                    }     //Of using CsvReader

                                                    con.Close();
                                                }         //Of using Oracle connection
                                                //Release the semaphore and decrease its counter so as the others threads
                                                //Could enter it and start execution
                                                slim.Release();
                                            }));           //Of the Async lambda method
                                        }
                                        catch (Exception ex)
                                        {
                                            Trace.TraceError("An exception has occured");
#if TRACE
                                            Trace.TraceError(ex.Message);
#endif
                                        }
                                    }
                                    else // Job is NOT complete
                                    {
                                        Trace.TraceError($"Thread {guid} has caught an error processing Bulk job {jobInfo?["id"]} for the {currObject} with the state {jobInfo["state"]}");
                                        source.Cancel();
                                    }
                                }
                                else
                                {
                                    Trace.TraceError($"Thread {guid} has caught an error creating Bulk job for the {currObject}");
                                    source.Cancel();
                                }
                            }, source.Token) //Per-run task defined
                            );
                        } while (needsToSubset && indexOfId < mixedIds.Count);
                        Trace.TraceInformation($"Thread {guid} is waiting for all runs ({runNumber}) to finish");
                        Task.WaitAll(idJobs.ToArray());
                        if (idJobs.Count(t=>t.IsCanceled || t.IsFaulted) != 0)
                        {
                            Trace.TraceError($"Thread {guid} has got {idJobs.Count(t => t.IsCanceled || t.IsFaulted)} batches not-pushed");
                        }
                        else
                        {
                            //Doing check of the number of uploaded rows
                            Trace.TraceInformation($"Thread {guid} is counting the number of rows uploaded into Oracl DB from {currObject}");
                            using (OracleConnection con = new OracleConnection())
                            {
                                con.ConnectionString = $"{ORCLcreds["ORCLConnectionString"].ReadString()}";
                                con.Open();
                                OracleCommand ocmd = new OracleCommand($"SELECT COUNT(*) FROM {tableName}", con);
                                object o = ocmd.ExecuteScalar();
                                int actualNumberOfRows = (int)((decimal)o);
                                Trace.TraceInformation($"Thread {guid} has expected to upload {(mixedIds.Count == 0 ? numberOfRecords : mixedIds.Count)} rows from " +
                                    $"the {currObject} into Oracle, actually uploaded {actualNumberOfRows}; " +
                                    $"{((actualNumberOfRows == (mixedIds.Count == 0 ? numberOfRecords : mixedIds.Count)) ? "upload has been successful" : "upload is done only partial")}");
                                con.Close();
                            }
                        }
                    }
                    else
                    {
                        Trace.TraceError($"Thread {guid} failed to read the {currObject}. Sending to the queue again");
                        listOfIds = listOfIds.Append(currObject).ToList();
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
        private static async Task<int> doWork(ICollection<string> listOfIds, IDictionary<string,string> creds, string obj, 
            ICryptoTransform cryptoTrans, PartialStreamWriter writer)
        {
            SynchronizedIds psid = new SynchronizedIds();
            int currentId;
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            HttpResponseMessage resp = null;
            int rowsBackedByThread = 0;
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
                        Trace.TraceError($"Thread {guid} has caught an exception while working in read mode.\n" +
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
                                    rowsBackedByThread++;
                                }
                            }
                        }
                    }
                    else
                    {
                        Trace.TraceError($"Thread {guid} has failed to read the {(listOfIds.ToList())[currentId]}. Sending to the queue again");
                        listOfIds.Add((listOfIds.ToList())[currentId]);
                    }
                    continue;
                }
                break;
            } while (true);
            Trace.TraceInformation($"A worker {guid} has finished the work. Backed up {rowsBackedByThread} rows.");
            return rowsBackedByThread;
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
        /// <returns></returns>.
        private static async Task<int> doWork(MinSizeQueue<KeyValuePair<string,string>> queue, IDictionary<string, string> creds, string obj,
            ICryptoTransform cryptoTrans, List<string> idList = null) 
        {
            Guid guid = Guid.NewGuid();
            Trace.TraceInformation($"A worker {guid} has started.");
            HttpResponseMessage response = null;
            int rowsBackedByThread = 0;
            while (true) 
            {
                KeyValuePair<string, string> att;
                if (minSizeQueue.TryDequeue(out att))
                {
                    if (idList == null || idList.Count == 0 || idList.Contains(att.Key))
                    {
                        byte[] valueBytes = null;
                        try
                        {
                            valueBytes = Convert.FromBase64String(att.Value);
                        }
                        catch
                        {
                            Trace.TraceError($"Thread {guid} has caught an error decoding Base64 value for {att.Key}");
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
                                            string json = "{\"Body\":\"" + decryptedValue + "\"}";
                                            try
                                            {
                                                response = await ReadFromSalesForce(new Uri(creds["serverUrl"] + "/sobjects/" + obj + "/" + att.Key),
                                                    creds, new HttpMethod("PATCH"), json);
                                            }
                                            catch (Exception ex)
                                            {
                                                Trace.TraceError($"Thread {guid} has caught an exception while working in write mode.\n" +
                                                    ex.Message);
                                            }

                                            if (response != null && response.Content != null && response.StatusCode == HttpStatusCode.OK)
                                            {
                                                Trace.TraceInformation($"Thread {guid} has successfully updated {att.Key}");
                                                rowsBackedByThread++;
                                            }
                                            else if (response.StatusCode == HttpStatusCode.NoContent)
                                            {
                                                Trace.TraceInformation($"Thread {guid} has obviously modified {att.Key}'s content, though \"no content\" has been returned.");
                                            }
                                            else
                                            {
                                                Trace.TraceError($"Thread {guid} failed to update {att.Key}. Code: {response?.StatusCode}");
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
                            Trace.TraceError($"Thread {guid}. {att.Key} didn't give any body for writing.");
                        }
                    }
                    else
                    {
                        Trace.TraceInformation($"Thread {guid} has skipped ID {att.Key} according to the given IDs list");
                        //Since skipping is done quite fast, need to add a small delay
                        Thread.Sleep(delayBetweenIDSkips);
                    }
                }
                else 
                {
                    minSizeQueue.Close();
                    break; 
                }
            }
            Trace.TraceInformation($"A worker {guid} has finished the work.");
            return rowsBackedByThread;
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
                        Trace.TraceError($"Thread {guid} has caught an error decoding Base64 value for {att.Key}");
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
                                            Trace.TraceError($"Thread {guid} has caught an error while working in Compare mode.\n" +
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
                                            Trace.TraceWarning($"Thread {guid} has failed to read #{currentId} - {att.Key}");
                                            writer.WriteLine(att.Key + ",SF_ERROR");
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Trace.TraceError($"{ex.Message}\noccured while trying to compare {att.Key} from thread {guid}");
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

        private static IDictionary<string, ProtectedString> OpenKeePassDB (SecureString Password, string pathKDBX, 
            string grpName, string entrName, bool UseWinLogon = false)
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
                        //otherwise the clause becomes too complicated for reading
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
                        if (grp.Name.Equals(grpName))
                        {
                            PwObjectList<PwEntry> entries = grp.GetEntries(false);
                            foreach (PwEntry ent in entries)
                            {
                                if (ent.Strings.ReadSafe("Title").Equals(entrName))
                                {
                                    dict.Add("Salt", new ProtectedString(true, ent.Strings.ReadSafe("Salt")));
                                    dict.Add("Password", new ProtectedString(true, ent.Strings.ReadSafe("Password")));
                                    dict.Add("AESPass", new ProtectedString(true, ent.Strings.ReadSafe("AESpassword")));
                                    dict.Add("UserName", new ProtectedString(true, ent.Strings.ReadSafe("UserName")));
                                    dict.Add("IV", new ProtectedString(true, ent.Strings.ReadSafe("IV")));
                                    dict.Add("SecurityToken", new ProtectedString(true, ent.Strings.ReadSafe("SecurityToken")));
                                    dict.Add("DataSource", new ProtectedString(true, ent.Strings.ReadSafe("DataSource")));
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
            int retries = 1;

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
                do
                {
                    response = await client.SendAsync(msg, HttpCompletionOption.ResponseContentRead);
                } 
                while (response?.Content == null && retries++ < numberOfRetries);
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
                    Console.Write("\rWait for {0} seconds or press any key to exit...", (--i).ToString("D2"));
                }), null, 1, 1000);
            });
            Task.Factory.StartNew(() => Console.ReadKey()).Wait(waittime);
        }

        private static string ComposeTableName(string ObjectName, Guid guid, string prefix)
        {
            return $"{prefix}_{ObjectName}_{guid.ToString("N").Substring(1,4)}";
        }

        private static string GeneratePrefix(int len)
        {
            Random random = new Random(DateTime.UtcNow.Millisecond);
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new string(Enumerable
                //Repeats the source string LEN time
                .Repeat(chars, len)
                //Selects from each source string only one random char
                .Select(s => s[random.Next(s.Length)])
                //Converts it to array from which the new string is constructed
                .ToArray());
        }

        private static void OnRowsCopied(object sender, OracleRowsCopiedEventArgs e)
        {
            Trace.TraceInformation($"Copied {e.RowsCopied} rows for the {((OracleBulkCopy)sender).DestinationTableName}");
        }
        #endregion Methods
    }

    class Options
    //https://github.com/gsscoder/commandline/wiki/Latest-Version
    {
        [Option('m', "workmode",
            Default = WorkingModes.Read,
            HelpText = "Set the working mode.\nRead - to read the data from the SF org and store them into a file (filer can be applied);" +
            "\nWrite - to read the data from encrypted file and store them back into the SF org;" +
            "\nCompare - to compare the data from the encrypted file and SF org;" +
            "\nPrepare - to prepare Crypto stuff in the given KDBX file (adds correctly filled AESPassword, Salt and IV records)" +
            "\nSubset - to store a subset in the RDB (filter can be applied).",
            MetaValue = "Read")]

        public WorkingModes WorkMode { get; set; }

        [Option('d', "salesforcedomain",
            Default = "test", MetaValue = "test",
            HelpText = "Sets a domain used to log into SalesForce, e.g. https://test.salesforce.com")]
        public string SalesForceDomain { get; set; }

        [Option('g', "groupname", Required = true, MetaValue = "EPAM",
            HelpText = "Gives the name of the group in the KeePass file where to look for the entry with SalesForce credentials")]
        public string GroupName { get; set; }

        [Option('e', "entryname", Required = true, MetaValue = "EPAM",
            HelpText = "Gives the name of the Entry within the group in the KeePass file with necessary credentials to connect to the SalesForce org")]
        public string EntryName { get; set; }

        [Option('k', "kdbxpath", Required = true,
            HelpText = "Sets the path to the KeePass file with the credentials. The file must not be key-file protected!",
            MetaValue = "D:\\creds.kdbx")]
        public string KDBXPath { get; set; }

        [Option('o', "sfobject", Default = SFObjectsWithAttachments.Document,
            HelpText = "Sets the SF object the body of attachments should be taken from",
            MetaValue = "Document")]
        public SFObjectsWithAttachments SFObject { get; set; }

        [Option('t', "targetfile",
            HelpText = "Sets the path to the target (source in case of write) file to store (to read) encrypted attachments to (from)",
            MetaValue = "D:\\Attach.bkp")]
        public string EcryptedAttachmentsTargetFile { get; set; }

        [Option('n', "threads", Default = 2, MetaValue = "2",
            HelpText = "Sets the number of concurrent threads")]
        public int NumberOfWorkingThreads { get; set; }

        [Option('c', "comppath",
            HelpText = "Sets path to the file with comparison results", MetaValue = "D:\\Doc_comp_res.dat")]
        public string ComparisonResultsFilePath { get; set; }

        [Option('l', "logfile",
            HelpText = "Sets the path to log file in additon to logging to the Console (if it's enabled by the next switch)",
            MetaValue = "D:\\Att_bkp.log")]
        public string LogFilePath { get; set; }

        [Option('x', "logtoconsole", Default = 1,
            HelpText = "Switches logging to Console mode on(<>0)/off(0). Might be useful since it doesn't waste time on UI output, though makes survey possible only through log file (if any provided).",
            MetaValue = "1")]
        public int LogToConsole { get; set; }

        [Option('f', "filter", Default = null,
            HelpText = "Takes a filter when running in the \"Read\" mode; \nWHERE keyword must be omitted;" +
            "text values must be enclosed in the single quotes." +
            "\nTo select necesssary objects when creating a Subset give pipe-separated list of object names, e.g. \"Account|Contact\"",
            MetaValue = "Id IN ('Id1','Id2')")]
        public string ReadModeFilter { get; set; }

        [Option('w', "winauth", Default = 0,
            HelpText = "If this parameter is set to any value other than 0 then access to the KeePass file will be done using the current windows login",
            MetaValue = "0")]
        public int UseWindowsAccount { get; set; }

        [Option("excludeobjects", Default = null, MetaValue = "D:\\ObjectsToExclude.json",
            HelpText = "Sets path to the JSON file that must contain the array with object names to be excluded from the listing."
            + "\nIt should list updateable objects that definitely do not contain sensitive information"
            + "\nImportant in subset mode. {\"ObjectsToExclude\":[\"Attachment\", \"Document\"]," +
            "\"FieldsToExclude:[{\"Account\":\"Jigsaw\"},{\"AnyObject\":\"Sic\"}]\"}")]
        public string PathToExcludeObjectsJson { get; set; }

        [Option("subsetpercentage", Default = 60, MetaValue = "50",
            HelpText ="Sets percentage of the subset. If it's not set then no subsetting is done and the whole object is processed.")]
        public int SubsetPercentage { get; set; }

        [Option("subsetnumofrec", Default = int.MaxValue, MetaValue = "100000",
            HelpText ="Sets the required (not more than) number of records in the subset. If not set and no value is given to the "+
            "\n\"subsetpercentage\" then no subsetting is done. The system defines the minimal value from both parameters")]
        public int SubsetNumberOfRecords { get; set; }

        [Option("orclgroupname", MetaValue = "EPAM_ORCL",
            HelpText = "Gives the name of the group where the ORCL credentials must be looked for")]
        public string ORCLGroupName { get; set; }
        
        [Option("orclentryname", MetaValue = "EPAM_ORCL",
            HelpText = "Gives the name of the entry where the ORCL credentials must be looked for. Must contain DataSource description.")]
        public string ORCLEntryName { get; set; }

        [Option("pushtimeout", MetaValue = "120", Default = 120,
            HelpText ="Sets the initial timeout value (seconds) for the packages to be pushed to the ORCL instance. Set it to a bigger value if you'll get too many warnings in the log.")]
        public int PushTimeout { get; set; }

        [Option("retries", MetaValue ="3", Default = 3,
            HelpText = "Sets the number of retries for push of the data batches; 1 - 10")]
        public int RetriesNumber { get; set; }
        
        [Option("maxrows", MetaValue ="1000", Default = int.MaxValue,
            HelpText = "Sets the maximal number of rows that one part of the back-up file could contain (>=1)")]
        public int MaxRowsInAPart { get; set; }

        [Option("idstorestore", MetaValue ="D:\\restore.ids",
            HelpText = "A list of IDs to be restored in write mode. A CSV file with only one column - \"ID\". If left empty all the IDs are restored")]
        public string PathToWriteIDs { get; set; }
    }

    enum SFObjectsWithAttachments
    {
        Attachment,
        Document,
        Note
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
        CredentialsAbsenseError = -5,
        NothingToReadError = -6,
        SourceFileDoesNorExistsError = -7,
        TargetDBConnectionError = -8,
        ObjectListError = -9,
        IDFileWrongFormatError = -10,
        OpenIDFileError = -11,
        UnknownError = -999
    }
}