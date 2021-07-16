using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Security;
using System.Text;
using System.Threading;
using System.Security.Cryptography;

namespace AsyncSalesForceAttachments
{
    public class SynchronizedIds
    {
        #region fields
        private static readonly string memMappedFileName = @"Local\PS_Ids";
        private static readonly long memMappedFileSize = 32;
        private static readonly MemoryMappedFile memMappedFile;
        private static readonly MemoryMappedViewAccessor memMappedFileAccessor;
        private static readonly string memMutexName = "EPAM_NOVARTIS_Salesforce_Attachments_Mutex";
        private static Mutex memMutex;
        #endregion
        static SynchronizedIds()
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

    public static class SecureStringExtension
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

    //https://stackoverflow.com/questions/530211/creating-a-blocking-queuet-in-net
    public class MinSizeQueue<T>
    {
        private readonly Queue<T> queue = new Queue<T>();
        private readonly int minSize;
        private bool closing;
        public MinSizeQueue(int minSize)
        {
            this.minSize = minSize;
        }

        public event EventHandler Dequeued;
        protected virtual void OnDequeued()
        {
            Dequeued?.Invoke(this, new DequeueEventArgs(queue.Count));
        }

        public void Enqueue(T item)
        {
            lock (queue)
            {
                while (queue.Count >= minSize)
                {
                    Monitor.Wait(queue);
                }
                queue.Enqueue(item);

                if (closing || queue.Count > minSize)
                {
                    //wake up any blocked dequeuers
                    Monitor.PulseAll(queue);
                }
            }
        }

        public void Close()
        {
            lock (queue)
            {
                closing = true;
                Monitor.Pulse(queue);
            }
        }
        public bool TryDequeue(out T value)
        {
            lock (queue)
            {
                while (queue.Count == 0)
                {
                    if (closing)
                    {
                        value = default(T);
                        return false;
                    }
                    Monitor.Wait(queue);
                }
                value = queue.Dequeue();
                if (queue.Count <= minSize)
                {
                    // wake up any blocked enqueuers
                    Monitor.PulseAll(queue);
                }
                return true;
            }
        }
    }

    public class DequeueEventArgs : EventArgs
    {
        public DequeueEventArgs(int num)
        {
            numberInQueue = num;
        }

        public int numberInQueue{ get; set; }
    }

    public class RndString
    {
        public static string GetRandomString(int len)
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            string chars = @"!@#$%^&*()_+~`/<>?.,:;*-=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            StringBuilder stringChars = new StringBuilder(len);
            
            Random random = new Random();

            byte[] b = new byte[len];

            rngCsp.GetBytes(b);

            for (int i = 0; i < len; i++)
            {
                stringChars.Append(chars[(int)b[i] % (chars.Length - 1)]);
            }

            return stringChars.ToString();
        }
    }
}