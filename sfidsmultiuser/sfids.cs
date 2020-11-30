using System.IO.MemoryMappedFiles;
using System.Security;
using System.Threading;

namespace PS_Ids_Async
{
    public class PowerShellId
    {
        private static readonly string memMappedFileName = @"Local\PS_Ids";

        private static readonly long memMappedFileSize = 32;

        private static readonly MemoryMappedFile memMappedFile;

        private static readonly MemoryMappedViewAccessor memMappedFileAccessor;

        private static readonly string memMutexName = "EPAM_NOVARTIS_ChineseData_Generation_Mutex";

        private static Mutex memMutex;

        static PowerShellId()
        {
            memMappedFile = MemoryMappedFile.CreateOrOpen(memMappedFileName, memMappedFileSize);
            memMappedFileAccessor = memMappedFile.CreateViewAccessor();
        }

        public int GetCurrentID()
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
            int i = memMappedFileAccessor.ReadInt32(0);
            memMappedFileAccessor.Write(0, i + 1);
            memMutex.ReleaseMutex();
            return i;
        }
    }
}

    public static class SecureStringExten
    {
        /// <summary>
        /// Returns a Secure string from the source string
        /// </summary>
        /// <param name="Source"></param>
        /// <returns></returns>
        public static SecureString ToSecureString(this string source)
        {
            if (string.IsNullOrWhiteSpace(source))
                return null;
            else
            {
                SecureString result = new SecureString();
                foreach (char c in source.ToCharArray())
                    result.AppendChar(c);
                return result;
            }
    }
}