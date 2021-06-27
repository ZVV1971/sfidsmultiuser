using Microsoft.VisualStudio.TestTools.UnitTesting;
using AsyncSalesForceAttachments;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AsyncSalesForceAttachments.Tests
{
    [TestClass()]
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