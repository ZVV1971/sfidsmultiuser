using PS_Ids_Async;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Security;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using KeePassLib.Security;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Serialization;
using KeePassLib.Collections;
using System.Xml.Linq;

namespace testconsole
{
    class Program
    {
        private static readonly string memMappedFileName = @"C:\Users\Uladzimir_Zakharenka\source\repos\ZVV1971\sfidsmultiuser\sfids.csv";
        private static readonly string pathToKeePassDb = @"C:\Users\Uladzimir_Zakharenka\source\repos\ZVV1971\sfidsmultiuser\LINX_GERMANY.kdbx";
        private static readonly string groupName = "HARMONYLACAN";
        private static readonly string entryName = "HARMONYLACAN";

        static void Main(string[] args)
        {
            SecureString securePwd = new SecureString();
            ConsoleKeyInfo key;

            var d = GetSalesForceSessionId();
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

            //Console.WriteLine(Marshal.PtrToStringAuto(Marshal.SecureStringToBSTR(securePwd)));

            Dictionary<string, ProtectedString> dic = OpenKeePassDB(securePwd);

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
            IStatusLogger statusLogger = new KeePassLib.Interfaces.NullStatusLogger();

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
    
        static Dictionary<string, string> GetSalesForceSessionId()
        {
            XDocument xml = XDocument.Parse( @"<?xml version=""1.0"" encoding=""utf-8""?>
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
                ");
            return new Dictionary<string, string>();
        }
    }
}