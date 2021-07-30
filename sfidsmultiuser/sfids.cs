using System;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Security;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Linq;
using System.ComponentModel.DataAnnotations;
using System.Collections;

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

    public class ConcurrentList<T> : IList<T>
    {
        #region Fields

        private IList<T> _internalList;

        private readonly object lockObject = new object();

        #endregion

        #region ctor

        public ConcurrentList()
        {
            _internalList = new List<T>();
        }

        public ConcurrentList(int capacity)
        {
            _internalList = new List<T>(capacity);
        }

        public ConcurrentList(IEnumerable<T> list)
        {
            _internalList = list.ToList();
        }

        #endregion

        public T this[int index]
        {
            get
            {
                return LockInternalListAndGet(l => l[index]);
            }

            set
            {
                LockInternalListAndCommand(l => l[index] = value);
            }
        }

        public int Count
        {
            get
            {
                return LockInternalListAndQuery(l => l.Count());
            }
        }

        public bool IsReadOnly => false;

        public void Add(T item)
        {
            LockInternalListAndCommand(l => l.Add(item));
        }

        public void Clear()
        {
            LockInternalListAndCommand(l => l.Clear());
        }

        public bool Contains(T item)
        {
            return LockInternalListAndQuery(l => l.Contains(item));
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            LockInternalListAndCommand(l => l.CopyTo(array, arrayIndex));
        }

        public IEnumerator<T> GetEnumerator()
        {
            return LockInternalListAndQuery(l => l.GetEnumerator());
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            lock (lockObject)
            {
                return ((IEnumerable)_internalList).GetEnumerator();
            }
        }

        public int IndexOf(T item)
        {
            return LockInternalListAndQuery(l => l.IndexOf(item));
        }

        public void Insert(int index, T item)
        {
            LockInternalListAndCommand(l => l.Insert(index, item));
        }

        public bool Remove(T item)
        {
            return LockInternalListAndQuery(l => l.Remove(item));
        }

        public void RemoveAt(int index)
        {
            LockInternalListAndCommand(l => l.RemoveAt(index));
        }

        #region Utilities

        protected virtual void LockInternalListAndCommand(Action<IList<T>> action)
        {
            lock (lockObject)
            {
                action(_internalList);
            }
        }

        protected virtual T LockInternalListAndGet(Func<IList<T>, T> func)
        {
            lock (lockObject)
            {
                return func(_internalList);
            }
        }

        protected virtual TObject LockInternalListAndQuery<TObject>(Func<IList<T>, TObject> query)
        {
            lock (lockObject)
            {
                return query(_internalList);
            }
        }
        #endregion
    }
}

namespace RepresentativeSubset
{
    public class SubsetHelper<T>
    {
        /// <summary>
        /// Perform subsetting of the original subset by ways of shuffling and cosequent quartering
        /// </summary>
        /// <param name="OriginalSet"></param>
        /// <param name="SubsetPercentage"></param>
        /// <param name="MinNumber">The minimal required number of records to return.<para></para></param>
        /// <returns></returns>
        public static IEnumerable<T> MakeSubset( IEnumerable<T> OriginalSet, 
            [Range(minimum: 0, maximum: 100, ErrorMessage = "Percentage out of range")] 
            int SubsetPercentage = 10, 
            int MinNumber = int.MaxValue)
        {
            if (SubsetPercentage <=0)
            {
                throw new ArgumentOutOfRangeException("SubsetPercentage", SubsetPercentage, "Argument cannot be less or equal to zero");
            }
            if (SubsetPercentage > 100)
            {
                throw new ArgumentOutOfRangeException("SubsetPercentage", SubsetPercentage, "Argument cannot be greater than 100");
            }

            List<T> ReturnValue = new List<T>(OriginalSet);

            int NumberOfRecords = Math.Min(MinNumber, ReturnValue.ToList<T>().Count * SubsetPercentage / 100);

            //Shuffle and take an half till the number is less or equal to the required one
            while (ReturnValue.Count >= NumberOfRecords)
            {
                ReturnValue = Quarter(Shuffle(ReturnValue)) as List<T>;
            }

            return ReturnValue;
        }
        /// <summary>
        /// Pefroms a kind of random mixing up of the original dataset
        /// </summary>
        /// <param name="OriginalSubset"></param>
        /// <returns>IEnumerable<typeparamref name="T"/></returns>
        public static IEnumerable<T> Shuffle (IEnumerable<T> OriginalSubset)
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            //Random rnd = new Random();
            List<T> lt = OriginalSubset.ToList<T>();
            List<T> rlst = new List<T>();
            byte[] RandomNumber = new byte[4];
            while (lt.Count > 0)
            {
                rngCsp.GetBytes(RandomNumber);
                UInt32 i = BitConverter.ToUInt32 (RandomNumber, 0);
                int NumberToPick = (int)(i % lt.Count);
                //int NumberToPick = rnd.Next(lt.Count);
                rlst.Add(lt[NumberToPick]);
                lt.RemoveAt(NumberToPick);
            }
            rngCsp.Dispose();
            return rlst;
        }
        
        /// <summary>
        /// Performs a quartering (selecting only even parts of the subset divided in four) 
        /// </summary>
        /// <param name="OriginalSubset"></param>
        /// <returns></returns>
        public static IEnumerable<T> Quarter (IEnumerable<T> OriginalSubset)
        {
            List<T> res = new List<T>();
            List<T> lt = OriginalSubset.ToList<T>();
            for (int i = 0; i < lt.Count; i++)
            {
                if (i % 2 == 0) res.Add(lt[i]);
            }

            return res;
        }
    }

    public enum SalesForceBulkJobStatus
    {
        /// <summary>
        /// The job has been created, and data can be added to the job.
        /// </summary>
        Open,
        /// <summary>
        /// No new data can be added to this job.Data associated with the job may be processed after a job is closed.You cannot edit or save a closed job.
        /// </summary>
        Closed,
        /// <summary>
        /// The job has been aborted.
        /// </summary>
        Aborted,
        /// <summary>
        /// The job has failed. Data that was successfully processed in the job cannot be rolled back.
        /// </summary>
        Failed,
        /// <summary>
        /// The job was processed by Salesforce. For Bulk API 2.0 jobs only.
        /// </summary>
        JobComplete,
        /// <summary>
        /// No new data can be added to this job. You can’t edit or save a closed job. For Bulk API 2.0 jobs only.
        /// </summary>
        UploadComplete,
        /// <summary>
        /// THe job si currently being processed
        /// </summary>
        InProgress
    }
}