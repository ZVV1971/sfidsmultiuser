using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

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
            Assert.AreEqual(i.ToList().Count, ot.ToList().Count);
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

            Assert.AreEqual(i.ToList().Count / 2, ot.ToList().Count);

        }

        [TestMethod("Measure execution time for Shuffling then Quartering for a comparatively big array ~1.000.000")]
        public void CheckExecutionTimeForShuffleAndQuarter()
        {
            string[] array1 = new string[1000000];
            for (int i = 0; i < array1.Length; i++) array1[i] = i.ToString();

            Stopwatch watch = Stopwatch.StartNew();

            IEnumerable<string> res = SubsetHelper<string>.Shuffle(array1);
            IEnumerable<string> ot = SubsetHelper<string>.Quarter(res);

            watch.Stop();

            Assert.IsTrue(watch.ElapsedMilliseconds <= 100, "The execution took {0} miliseconds", watch.ElapsedMilliseconds);
        }

        [TestMethod("Measure execution time for Shuffling for a comparatively big array ~1.000.000")]
        public void CheckExecutionTimeForShuffle()
        {
            string[] array1 = new string[1000000];
            for (int i = 0; i < array1.Length; i++) array1[i] = i.ToString();

            Stopwatch watch = Stopwatch.StartNew();

            IEnumerable<string> res = SubsetHelper<string>.Shuffle(array1);

            watch.Stop();

            Assert.IsTrue(watch.ElapsedMilliseconds <= 100, "The execution took {0} miliseconds", watch.ElapsedMilliseconds);
        }
    }
}