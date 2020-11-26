using PS_Ids_Async;
using System;
using System.Threading;

namespace testconsole
{
    class Program
    {
        static void Main(string[] args)
        {
            PS_Ids_Async.PowerShellId psid = new PowerShellId();
            string c = " ";
            while (true)
            {
                c = psid.GetCurrentID();
                if (!c.Equals(string.Empty)) { Console.WriteLine(c); Thread.Sleep(100); continue; }
                break;
            }
            Console.ReadKey();
        }
    }
}
