using System.IO.MemoryMappedFiles;
using System.Threading;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace PS_Ids_Async
{
    public class PowerShellId
    {
        private static readonly string memMappedFileName = @"d:\Projects\Chinese Data Generation\sfidsmultiuser\sfids.csv";//@"Local\PS_Ids";

        private static readonly MemoryMappedFile memMappedFile;

        private static readonly string memMappedOffsetFileName = @"Local\PS_Ids";

        private static readonly long memMappedFileSize = 32;

        private static readonly MemoryMappedFile memMappedOffsetFile;

        private static readonly MemoryMappedViewAccessor memMappedFileOffsetAccessor;

        private static readonly MemoryMappedViewAccessor memMappedFileAccessor;

        private static readonly string memMutexName = "EPAM_NOVARTIS_SalesForce_IDs_Multiuser_Mutex";

        private static Mutex memMutex;

        private static readonly int SFIDlength = "001i000001AWbWugta".Length;

        private static long offset = 0;

        private static long fLength;

        private static string memName = "mappedName";
                
        static PowerShellId()
        {
            memMappedOffsetFile = MemoryMappedFile.CreateOrOpen(memMappedOffsetFileName, memMappedFileSize);
            memMappedFileOffsetAccessor = memMappedOffsetFile.CreateViewAccessor();

            if (File.Exists(memMappedFileName))
            {
                fLength = (new FileInfo(memMappedFileName)).Length;
                try
                {
                    memMappedFile = MemoryMappedFile.CreateFromFile(memMappedFileName, FileMode.Open, memName);
                }
                catch
                {
                    memMappedFile = MemoryMappedFile.OpenExisting(memName);
                }
                memMappedFileAccessor = memMappedFile.CreateViewAccessor(offset, fLength);
            }
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
}