using System.IO.MemoryMappedFiles;
using System.Threading;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System;
using System.Xml.Linq;
using System.Xml;

namespace PS_Ids_Async
{
    public class PowerShellId
    {
        private static MemoryMappedFile memMappedFile;

        private static readonly string memMappedOffsetFileName = @"Local\PS_Ids";

        private static readonly long memMappedFileSize = 32;

        private static MemoryMappedFile memMappedOffsetFile;

        private static MemoryMappedViewAccessor memMappedFileOffsetAccessor;

        private static MemoryMappedViewAccessor memMappedFileAccessor;

        private static readonly string memMutexName = "EPAM_NOVARTIS_SalesForce_IDs_Multiuser_Mutex";

        private static Mutex memMutex;

        private static readonly int SFIDlength = "001i000001AWbWugta".Length;

        private static long offset = 0;

        private static long fLength;

        private static string memName = "mappedName";

        private static PowerShellId _temp;
        
        private PowerShellId() {}

        public static PowerShellId Create(string FileToOpen)
        {
            _temp = new PowerShellId();
            
            memMappedOffsetFile = MemoryMappedFile.CreateOrOpen(memMappedOffsetFileName, memMappedFileSize);
            memMappedFileOffsetAccessor = memMappedOffsetFile.CreateViewAccessor();

            CurrentUserSecurity curUS = new CurrentUserSecurity();
            if (File.Exists(FileToOpen) && curUS.HasAccess(new FileInfo(FileToOpen), FileSystemRights.ReadData & FileSystemRights.Write))
            {
                fLength = (new FileInfo(FileToOpen)).Length;
                try
                {
                    memMappedFile = MemoryMappedFile.CreateFromFile(FileToOpen, FileMode.Open, memName);
                }
                catch (Exception ex)
                {
                    memMappedFile = MemoryMappedFile.OpenExisting(memName);
                }
                memMappedFileAccessor = memMappedFile.CreateViewAccessor(offset, fLength);
            }

            return _temp;
        }

        ~PowerShellId()
        {
            memMappedFileAccessor.Dispose();
            memMappedFile.Dispose();
        }

        public string GetCurrentID()
        {
            SFIDclass sFID = new SFIDclass();
            offset = GetCurrentOffset();
            if (offset < fLength && fLength - offset > SFIDlength)
            {
                memMappedFileAccessor.Read(offset, out sFID.sfid);
                unsafe
                {
                    fixed (byte* ptr = sFID.sfid.vs)
                    {
                        byte[] bytes = new byte[18];
                        int index = 0;
                        for (byte* counter = ptr; *counter != 0; counter++)
                        {
                            bytes[index++] = *counter;
                        }
                        return Encoding.ASCII.GetString(bytes);
                    }
                }
            }
            return "";
        }

        private long GetCurrentOffset()
        {
            try
            {
                memMutex = Mutex.OpenExisting(memMutexName);
            }
            catch
            {
                memMutex = new Mutex(false, memMutexName);
            }
            memMutex.WaitOne();
            long i = memMappedFileOffsetAccessor.ReadInt64(0);
            memMappedFileOffsetAccessor.Write(0, i + SFIDlength + 2);
            memMutex.ReleaseMutex();
            return i;
        }

        [StructLayout(LayoutKind.Explicit, Size = 18)]
        internal unsafe struct SFID
        {
            [FieldOffset(0)]
            public fixed byte vs[18];
        }

        internal unsafe class SFIDclass
        {
            public SFID sfid;
        }
    }

    public class CurrentUserSecurity
    {
        WindowsIdentity _currentUser;
        WindowsPrincipal _currentPrincipal;

        public CurrentUserSecurity()
        {
            _currentUser = WindowsIdentity.GetCurrent();
            _currentPrincipal = new WindowsPrincipal(_currentUser);
        }

        public bool HasAccess(DirectoryInfo directory, FileSystemRights right)
        {
            // Get the collection of authorization rules that apply to the directory.
            AuthorizationRuleCollection acl = directory.GetAccessControl()
                .GetAccessRules(true, true, typeof(SecurityIdentifier));
            return HasFileOrDirectoryAccess(right, acl);
        }

        public bool HasAccess(FileInfo file, FileSystemRights right)
        {
            // Get the collection of authorization rules that apply to the file.
            AuthorizationRuleCollection acl = file.GetAccessControl()
                .GetAccessRules(true, true, typeof(SecurityIdentifier));
            return HasFileOrDirectoryAccess(right, acl);
        }

        private bool HasFileOrDirectoryAccess(FileSystemRights right,
                                              AuthorizationRuleCollection acl)
        {
            bool allow = false;
            bool inheritedAllow = false;
            bool inheritedDeny = false;

            for (int i = 0; i < acl.Count; i++)
            {
                var currentRule = (FileSystemAccessRule)acl[i];
                // If the current rule applies to the current user.
                if (_currentUser.User.Equals(currentRule.IdentityReference) ||
                    _currentPrincipal.IsInRole(
                                    (SecurityIdentifier)currentRule.IdentityReference))
                {

                    if (currentRule.AccessControlType.Equals(AccessControlType.Deny))
                    {
                        if ((currentRule.FileSystemRights & right) == right)
                        {
                            if (currentRule.IsInherited)
                            {
                                inheritedDeny = true;
                            }
                            else
                            { // Non inherited "deny" takes overall precedence.
                                return false;
                            }
                        }
                    }
                    else if (currentRule.AccessControlType
                                                    .Equals(AccessControlType.Allow))
                    {
                        if ((currentRule.FileSystemRights & right) == right)
                        {
                            if (currentRule.IsInherited)
                            {
                                inheritedAllow = true;
                            }
                            else
                            {
                                allow = true;
                            }
                        }
                    }
                }
            }

            if (allow)
            { // Non inherited "allow" takes precedence over inherited rules.
                return true;
            }
            return inheritedAllow && !inheritedDeny;
        }
    }

    public static class DocumentExtensions
    {
        public static XmlDocument ToXmlDocument(this XDocument xDocument)
        {
            var xmlDocument = new XmlDocument();
            using (var xmlReader = xDocument.CreateReader())
            {
                xmlDocument.Load(xmlReader);
            }
            return xmlDocument;
        }

        public static XDocument ToXDocument(this XmlDocument xmlDocument)
        {
            using (var nodeReader = new XmlNodeReader(xmlDocument))
            {
                nodeReader.MoveToContent();
                return XDocument.Load(nodeReader);
            }
        }
    }
}