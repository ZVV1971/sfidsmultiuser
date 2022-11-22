using AsyncSalesForceAttachments;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static AsyncSalesForceAttachments.PartialStreamWriter;

namespace AsyncSalesForceAttachments.Tests
{
    [TestClass]
    public class RndStringTests
    {
        [TestMethod("Checks the length of the string returned")]
        public void GetRandomStringTestLength()
        {
            Random r = new Random(12);
            int i = r.Next(1, 100);
            Assert.AreEqual(RndString.GetRandomString(i).Length, i);
        }

        [TestMethod("Checks that generated string of the same length are different")]
        public void GetRandomStringTestDifferent()
        {
            Random r = new Random(121);
            int i = r.Next(10, 100);
            Assert.AreNotEqual(RndString.GetRandomString(i), RndString.GetRandomString(i));
        }

        public void GetCurrentIDTest()
        {

        }
    }
}

namespace RepresentativeSubset.Tests
{
    [TestClass]
    public class ReprSubTests
    {
        private int milisecsForLargeShuffle = 80000;
        private int milisecsForLargeQuartering = 2000;

        [TestMethod("Test the outlayers of range of the percentange")]
        public void SetWrongPercentageReprSubset()
        {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => {
                    SubsetHelper<int>.MakeSubset(OriginalSet: new int[] { 1, 2 }, SubsetPercentage: 200); ; 
                      }
                );
        }

        [TestMethod("Test the correct value in range of the percentange")]
        public void SetValidPercentageReprSubset()
        { 
            SubsetHelper<int>.MakeSubset(OriginalSet: new int[] { 1, 2 }, SubsetPercentage: 50);
        }

        [TestMethod("Checks if the number of input records corresponds ot the number of output ones")]
        public void CheckShufflingReturnEqualNumberOfRows()
        {
            IEnumerable<int> i = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            IEnumerable<int> ot = SubsetHelper<int>.Shuffle(i);
            Assert.AreEqual(i.ToList().Count, ot.ToList().Count, $"Excpected {i.ToList().Count}; actial {ot.ToList().Count}");
        }

        [TestMethod("Checks that the input is not equal to the output")]
        public void CheckEqualityOfShuffled()
        {
            IEnumerable<int> i = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            IEnumerable<int> ot = SubsetHelper<int>.Shuffle(i);

            Assert.IsFalse(i.Equals(ot));
        }

        [TestMethod("Checks whether the quarting method returns exctly one half of the original subset")]
        public void CheckQuarting()
        {
            IEnumerable<int> i = new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            IEnumerable<int> ot = SubsetHelper<int>.Quarter(i);

            Assert.AreEqual(i.ToList().Count / 2, ot.ToList().Count, $"{i.ToArray().Length} - {ot.ToArray().Length}");

        }

        [TestMethod("Measure execution time for Shuffling then Quartering for a comparatively big array ~1.000.000")]
        public void CheckExecutionTimeForShuffleAndQuarter()
        {
            string[] array1 = new string[1000000];
            for (int i = 0; i < array1.Length; i++) array1[i] = i.ToString();

            Stopwatch watch = Stopwatch.StartNew();

            _= SubsetHelper<string>.MakeSubset(array1);
            
            watch.Stop();

            Assert.IsTrue(watch.ElapsedMilliseconds <= milisecsForLargeQuartering, "The execution took {0} miliseconds, but we expected {1}", watch.ElapsedMilliseconds, milisecsForLargeQuartering);
        }

        [TestMethod("Measure execution time for Shuffling for a comparatively big array ~13.000.000")]
        public void CheckExecutionTimeForShuffle()
        {
            string[] array1 = new string[13000000];
            for (int i = 0; i < array1.Length; i++) array1[i] = i.ToString();

            Debug.WriteLine("Finished creation of the array");
            Stopwatch watch = Stopwatch.StartNew();

            _ = SubsetHelper<string>.Shuffle(array1);

            watch.Stop();

            Assert.IsTrue(watch.ElapsedMilliseconds <= milisecsForLargeShuffle, "The execution took {0} miliseconds, but {1} was expected", watch.ElapsedMilliseconds, milisecsForLargeShuffle);
        }

        [TestMethod("Check number of returned records for a comparatively big array ~1.000.000")]
        public void CheckNumberOfRecordsMakeSubset_LessOrEqual()
        {
            int requiredCount = 499000;
            string[] array1 = new string[1000000];
            for (int i = 0; i < array1.Length; i++) array1[i] = i.ToString();

            IEnumerable<string> res = SubsetHelper<string>.MakeSubset(array1, MinNumber: requiredCount);

            Assert.IsTrue(res.Count() <= requiredCount, $"The count is {res.Count()}");
        }

        [TestMethod("Check correctness of subset parameters - according to the minimal number")]
        public void CheckCorectnessOfSubsetParameters_MinNumber ()
        {
            int requiredCount = 4990;
            string[] array1 = new string[10000];
            for (int i = 0; i < array1.Length; i++) array1[i] = i.ToString();

            IEnumerable<string> res = SubsetHelper<string>.MakeSubset(array1, SubsetPercentage: 50, MinNumber: requiredCount);

            Assert.IsTrue(res.Count() <= requiredCount, $"The count is {res.Count()}");
        }

        [TestMethod("Check correctness of subset parameters - according to the subset percentage")]
        public void CheckCorectnessOfSubsetParameters_SubsetPercentage()
        {
            int requiredCount = 4990;
            int perc = 40;
            int numberOfRecords = 100000;
            string[] array1 = new string[numberOfRecords];
            for (int i = 0; i < array1.Length; i++) array1[i] = i.ToString();

            IEnumerable<string> res = SubsetHelper<string>.MakeSubset(array1, SubsetPercentage: perc, MinNumber: requiredCount);

            Assert.IsTrue(res.Count() <= requiredCount, $"The count is {res.Count()}");
            Assert.IsTrue(res.Count() <= numberOfRecords * perc / 100);
        }
    }
}

namespace MultiPartStreamTests
{
    [TestClass]
    public class MultiPartWriterTests
    {
        string path;
        string testString;
        int numberOfParts;
        int numberOfLines;
        int numberOfThreads;
        int numberOfTries = 10;
        TimeSpan timeIntervalBetweenTries = TimeSpan.FromMilliseconds(1000);


        [TestInitialize]
        public void Initialize()
        {
            path = Environment.GetFolderPath(Environment.SpecialFolder.Personal) + @"\backup.csv";
            testString = RndString.GetRandomString(500);
            numberOfParts = 40;
            numberOfLines = 500;
            numberOfThreads = 8;
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (File.Exists(path))
            {
                DirectoryInfo dir = new DirectoryInfo(Path.GetDirectoryName(path));

                foreach (var file in dir.EnumerateFiles("backup.csv.part????"))
                {
                    var tries = 0;
                    while (true)
                    {
                        try
                        {
                            File.Open(file.FullName, FileMode.Open, FileAccess.Write, FileShare.Delete);
                            file.Delete();
                            break;
                        }
                        catch (IOException e)
                        {
                            if (!IsFileLocked(e))
                                throw;
                            if (++tries > numberOfTries)
                                throw new Exception("The file is locked too long: " + e.Message, e);
                            Thread.Sleep(timeIntervalBetweenTries);
                        }
                    }
                }
                File.Delete(path);
            }
        }

        [TestMethod("Checks whether the number of files is equal to the number of parts created by the method")]
        public void checkNumberOfParts()
        {
            using (PartialStreamWriter partialStream = new PartialStreamWriter(numberOfLines, path, false, Encoding.ASCII))
            {
                for (int i = 0; i < numberOfParts; i++)
                {
                    partialStream.WriteLine(testString);
                }
            }

            Assert.IsTrue(File.Exists(path));
            for (int j = 0; j < numberOfParts/numberOfLines -1; j++)
            {
                Assert.IsTrue(File.Exists(path + $".part{j++.ToString("D4")}"));
            }
        }

        [TestMethod("Checks whether the number of files is equal to the number of parts created by the PartialStreamWriter through multiple threads")]
        public void checkNumberOfPartsMultiThread()
        {
            SynchronizedIds counter = new SynchronizedIds();
            List<Task> taskList = new List<Task>(numberOfThreads);

            using (PartialStreamWriter partialStream = new PartialStreamWriter(numberOfLines, path, false, Encoding.ASCII))
            {
                for (int k = 0; k < numberOfThreads; k++)
                {
                    taskList.Add(Task.Run(() =>
                    {
                        while (counter.GetCurrentID() < numberOfParts)
                        {
                            partialStream.WriteLine(testString);
                        }
                    }));
                }
                Task.WaitAll(taskList.ToArray());
            }

            Assert.IsTrue(File.Exists(path));
            for (int j = 0; j < numberOfParts/numberOfLines - 1; j++)
            {
                Assert.IsTrue(File.Exists(path + $".part{j.ToString("D4")}"));
            }
        }

        [TestMethod("Checks whether the event are raised in due quantity")]
        public void checkEventIsRaised()
        {
            SynchronizedIds counter = new SynchronizedIds();
            List<Task> taskList = new List<Task>(numberOfThreads);
            List<NewPartStartedEventArgs> eventList = new List<NewPartStartedEventArgs>();

            using (PartialStreamWriter partialStream = new PartialStreamWriter(numberOfLines, path, false, Encoding.ASCII))
            {
                partialStream.NewPartStarted += delegate (object sender, NewPartStartedEventArgs e)
                {
                    eventList.Add(e);
                };

                for (int k = 0; k < numberOfThreads; k++)
                {
                    taskList.Add(Task.Run(() =>
                    {
                        while (counter.GetCurrentID() < numberOfParts)
                        {
                            partialStream.WriteLine(testString);
                        }
                    }));
                }
                Task.WaitAll(taskList.ToArray());
            }

            Assert.AreEqual(Math.Ceiling(numberOfParts / (double)numberOfLines) - 1, eventList.Count, $"Actual count is {eventList.Count} expected {(int)Math.Ceiling(numberOfParts / (double)numberOfLines) - 1}");
        }

        [TestMethod("Checks if the system can correctly find all the parts created by the PartialStreamWriter")]
        public void findAllParts()
        {
            using (PartialStreamWriter partialStream = new PartialStreamWriter(numberOfLines, path, false, Encoding.ASCII))
            {
                for (int i = 0; i < numberOfParts; i++)
                {
                    partialStream.WriteLine(testString);
                }
            }

            List<string> files = new List<string>
            {
                path
            };
            files.AddRange(Directory.GetFiles(Path.GetDirectoryName(path), Path.GetFileName(path) + ".part????"));

            Assert.AreEqual(files.Count, Math.Ceiling(numberOfParts / (double)numberOfLines));
        }

        [TestMethod("Check correctnes when reading from multiple parts")]
        public void readFromMultipleParts()
        {
            if (!File.Exists(path))
            {
                using (PartialStreamWriter partialStream = new PartialStreamWriter(numberOfLines, path, false, Encoding.ASCII))
                {
                    for (int i = 0; i < numberOfParts; i++)
                    {
                        for (int j = 0; j < numberOfLines; j++)
                        {
                            partialStream.WriteLine(testString);
                        }
                    }
                }
            }

            MinSizeQueue<string> minSizeQueue = new MinSizeQueue<string>(numberOfThreads);

            List<string> eventList = new List<string>();
            minSizeQueue.Dequeued += delegate (object sender, QueueEventArgs e)
            {
                Console.WriteLine(e.numberInQueue);
                eventList.Add(e.numberInQueue.ToString());
            };
            minSizeQueue.Enqueued += delegate (object sender, QueueEventArgs e)
            {
                //Console.WriteLine($"Enqueued {e.numberInQueue}");
            };

            Task enq = Task.Factory.StartNew(() =>
            {
                using (StreamReader stream = new StreamReader(path, Encoding.ASCII, false, 100000))
                {
                    string line;
                    while (true)
                    {
                        line = stream.ReadLine();
                        if (line == null)
                        {
                            minSizeQueue.Close();
                            break;
                        }
                        minSizeQueue.Enqueue(line);
                    }
                }
            });

            Directory.GetFiles(Path.GetDirectoryName(path), Path.GetFileName(path) + ".part????")
                .ToList()
                .ForEach(t => Task.Factory.StartNew(() =>
                  {
                      using (StreamReader stream = new StreamReader(t, Encoding.ASCII, false, 100000))
                      {
                          string line;
                          while (true)
                          {
                              line = stream.ReadLine();
                              if (line == null)
                              {
                                  minSizeQueue.Close();
                                  break;
                              }
                              minSizeQueue.Enqueue(line);
                          }
                      }
                  }));

            //Create dequeuers
            List<Task> deq = new List<Task>();
            for (int i = 0; i < numberOfThreads; i++)
            {
                deq.Add(Task.Factory.StartNew(() =>
                {
                    string value;
                    while (true)
                    {
                        if (minSizeQueue.TryDequeue(out value))
                        {
                            Console.WriteLine(value);
                            Thread.Sleep(10);
                        }
                        else
                        {
                            minSizeQueue.Close();
                            break;
                        }
                    }
                }));
            }

            deq.Add(enq);
            Task.WaitAll(deq.ToArray<Task>());
            Assert.AreEqual(eventList.Count, numberOfParts*numberOfLines);
        }

        private void runTask(object state)
        {
            MinSizeQueue<string> minSizeQueue = ((Tuple<string, MinSizeQueue<string>>)state).Item2;
            using (StreamReader stream = new StreamReader(((Tuple<string, MinSizeQueue<string>>)state).Item1, Encoding.ASCII, false, 100000))
            {
                string line;
                while (true)
                {
                    line = stream.ReadLine();
                    if (line == null)
                    {
                        minSizeQueue.Close();
                        break;
                    }
                    minSizeQueue.Enqueue(line);
                }
            }
        }

        private static bool IsFileLocked(IOException exception)
        {
            int errorCode = Marshal.GetHRForException(exception) & ((1 << 16) - 1);
            return errorCode == 32 || errorCode == 33;
        }
    }
}

namespace MinSizeQueueTests
{
    [TestClass]
    public class MinSizeQueueTestsClass
    {
        string path;
        string testString;
        int numberOfRows;
        int numberOfThreads;
        MinSizeQueue<string> minSizeQueue;

        [TestInitialize]
        public void InitializeFiles()
        {
            path = @"C:\Users\Uladzimir_Zakharenka\Documents\backup_syncho.csv";
            testString = RndString.GetRandomString(4000);
            numberOfRows = 10000;
            minSizeQueue = new MinSizeQueue<string>(1);
            numberOfThreads = 10;

            using (StreamWriter stream = new StreamWriter(path, false, Encoding.ASCII))
            {
                for (int i = 0; i < numberOfRows; i++)
                {
                    stream.WriteLine(testString);
                }
            }
        }

        [TestMethod]
        public void CheckEventsGenerated()
        {
            MinSizeQueue<string> minSizeQueue = new MinSizeQueue<string>(numberOfThreads);
            List<string> eventList = new List<string>();
            minSizeQueue.Dequeued += delegate (object sender, QueueEventArgs e) 
            {
                Console.WriteLine(e.numberInQueue);
                eventList.Add(e.numberInQueue.ToString());
            };
            minSizeQueue.Enqueued += delegate (object sender, QueueEventArgs e)
            {
                Console.WriteLine($"Enqueued {e.numberInQueue}");
            };

            Task enq = Task.Factory.StartNew(() =>
            {
                using (StreamReader stream = new StreamReader(path, Encoding.ASCII, false, 100000))
                {
                    string line;
                    while (true)
                    {
                        line = stream.ReadLine();
                        if (line == null)
                        {
                            minSizeQueue.Close();
                            break;
                        }
                        minSizeQueue.Enqueue(line);
                    }
                }
            });

            //Create dequeuers
            List<Task> tasks = new List<Task>();
            for (int i = 0; i < numberOfThreads; i++) 
            {
                tasks.Add(Task.Factory.StartNew(() =>
                {
                    string value;
                    while (true)
                    {
                        if (minSizeQueue.TryDequeue(out value))
                        {
                        //Console.WriteLine(value);
                    }
                        else
                        {
                            minSizeQueue.Close();
                            break;
                        }
                    }
                })); 
            }

            tasks.Add(enq);
            Task.WaitAll(tasks.ToArray<Task>());
            Assert.AreEqual(eventList.Count, numberOfRows);
        }
    }
}

namespace JsonNotInTests
{
    [TestClass]
    public class json_notin
    {
        public static string solution_dir = Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)).FullName).FullName;
        string path_to_account_fields = Path.Combine(solution_dir, "Account_fields.json");
        string path_to_objects = Path.Combine(solution_dir, "ObjectsToExclude.json");
        JArray JFields;
        JArray JObjects;

        [TestInitialize]
        public void FillArrays()
        {
                JFields = JArray.Parse(File.ReadAllText(path_to_account_fields));
                JObjects = JObject.Parse(File.ReadAllText(path_to_objects))["FieldsToExclude"] as JArray;
        }

        [TestMethod]
        public void CheckNumberOfFields()
        {
            Assert.AreEqual(JFields.Count, 62);
        }

        [TestMethod]
        public void CheckNumberofFieldsBeforeExclusion()
        {
            Assert.AreEqual(34,
                JFields.Where(t => t["updateable"].ToString().Equals("True")
                                        && !t["type"].ToString().Equals("boolean")
                                        && !t["type"].ToString().Equals("picklist")
                                        && !t["type"].ToString().Equals("reference")
                                        && !t["type"].ToString().Equals("double"))
                                //Include all the references
                                .Concat(JFields.Where(x => x["type"].ToString().Equals("reference"))).Count()
                );
        }

        [TestMethod]
        public void CheckNumberOfFieldsToExcludeInAccountObject()
        {
            var an = JObjects.Descendants().OfType<JProperty>().Where(p => p.Name == "AnyObject" || p.Name == "Account");

            Assert.AreEqual(2,
                an.Count()
                );
        }

        [TestMethod]
        public void CheckNumberofFieldsAfterExclusion()
        {
            var an = JObjects.Descendants().OfType<JProperty>().Where(p => p.Name == "AnyObject" || p.Name == "Account").Values().Distinct();
            var bn = JFields.Where(t => t["updateable"].ToString().Equals("True")
                                        && !t["type"].ToString().Equals("boolean")
                                        && !t["type"].ToString().Equals("picklist")
                                        && !t["type"].ToString().Equals("reference")
                                        && !t["type"].ToString().Equals("double")
                                        && !t["type"].ToString().Equals("multipicklist"))
                                //Include all the references
                                .Concat(JFields.Where(x => x["type"].ToString().Equals("reference")));
            var cn = bn.Where(d => !an.Contains(d["name"])).Select(s=> new { name = s["name"], type = s["type"] });
            Assert.AreEqual(32,
                                bn.Where(x => !an.Contains(x["name"]))
                                .Count()
                );
        }
    }
}