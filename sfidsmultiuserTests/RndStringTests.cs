using AsyncSalesForceAttachments;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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

            Assert.IsTrue(watch.ElapsedMilliseconds <= 100, "The execution took {0} miliseconds", watch.ElapsedMilliseconds);
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

            Assert.IsTrue(watch.ElapsedMilliseconds <= 100, "The execution took {0} miliseconds", watch.ElapsedMilliseconds);
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
        [TestMethod]
        public void checkNumberOfParts()
        {
            string testString = RndString.GetRandomString(5000);
            string path = @"C:\Users\Uladzimir_Zakharenka\Documents\backup.csv";
            int numberOfParts = 10;
            using (PartialStreamWriter partialStream = new PartialStreamWriter(1, path, false, Encoding.ASCII))
            {
                for (int i = 0; i < numberOfParts; i++)
                {
                    partialStream.WriteLine(testString);
                }
            }

            Assert.IsTrue(File.Exists(path));
            for (int j = 0; j < numberOfParts -1; j++)
            {
                Assert.IsTrue(File.Exists(path + $".part{j++.ToString("D3")}"));
            }
        }

        [TestMethod]
        public void checkNumberOfPartsMultiThread()
        {
            string testString = RndString.GetRandomString(5000);
            string path = @"C:\Users\Uladzimir_Zakharenka\Documents\backup.csv";
            
            int numberOfParts = 100;
            int numberOfThreads = 13;
            int numberOfLines = 5;
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
                Assert.IsTrue(File.Exists(path + $".part{j.ToString("D3")}"));
            }
        }

        [TestMethod]
        public void checkEvenrIsRaised()
        {
            string testString = RndString.GetRandomString(5000);
            string path = @"C:\Users\Uladzimir_Zakharenka\Documents\backup.csv";

            int numberOfParts = 100;
            int numberOfThreads = 13;
            int numberOfLines = 5;
            SynchronizedIds counter = new SynchronizedIds();
            List<Task> taskList = new List<Task>(numberOfThreads);
            List<string> eventList = new List<string>();

            using (PartialStreamWriter partialStream = new PartialStreamWriter(numberOfLines, path, false, Encoding.ASCII))
            {
                partialStream.NewPartStarted += delegate (object sender, NewPartStartedEventArgs e)
                {
                    Console.WriteLine($"New part has been started {e.newPartPath}");
                    eventList.Add(e.newPartPath);
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

            Assert.AreEqual((int)(numberOfParts / numberOfLines) - 1, eventList.Count, $"Actual count is {eventList.Count} expected {(int)(numberOfParts / numberOfParts) - 1}");
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