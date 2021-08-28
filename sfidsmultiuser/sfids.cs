using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

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
        public delegate void QueuedEventHandler(object sender, QueueEventArgs e);

        private readonly Queue<T> queue = new Queue<T>();
        private readonly int minSize;
        private bool closing;

        /// <summary>
        /// Initializes a new instance of MinSizeQueue with default number of slots = 10
        /// </summary>
        public MinSizeQueue() : this(10) { }
        
        /// <summary>
        /// Initializes a new instance of the MinSizeQueue with the <paramref name="minSize"/> number of slots
        /// </summary>
        /// <param name="minSize">The parameter indicating then the queue should wake up any blocked enqueers </param>
        public MinSizeQueue(int minSize)
        {
            this.minSize = minSize;
        }

        public event QueuedEventHandler Dequeued;
        protected virtual void OnDequeued()
        {
            Dequeued?.Invoke(this, new QueueEventArgs(queue.Count, true));
        }

        public event QueuedEventHandler Enqueued;

        protected virtual void OnEnqueued()
        {
            Enqueued?.Invoke(this, new QueueEventArgs(queue.Count, false));
        }

        public void Enqueue(T item)
        {
            lock (queue)
            {
                while (queue.Count > minSize)
                {
                    Monitor.Wait(queue);
                }
                queue.Enqueue(item);
                OnEnqueued();

                if (closing || queue.Count >= minSize)
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
                Monitor.PulseAll(queue);
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
                OnDequeued();
                if (queue.Count <= minSize)
                {
                    // wake up any blocked enqueuers
                    Monitor.PulseAll(queue);
                }
                return true;
            }
        }
    }
    /// <summary>
    /// Holds the current numberInQueue (after the operation Enqueue / Dequeue has been done)
    /// Dequeued the direction of the operation; true - dequeuing; false - enqueuing
    /// </summary>
    public class QueueEventArgs : EventArgs
    {
        public QueueEventArgs(int num, Boolean dequeued)
        {
            numberInQueue = num;
            this.dequeued = dequeued;
        }

        public int numberInQueue { get; }
        public bool dequeued { get; }
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
    
    public class PartialStreamWriter : MarshalByRefObject, IDisposable
    {
        private int _maxRows;
        private string _path;
        private string _currentPath;
        private TextWriter _streamWriter;
        private int _counter;
        private int _currentPart;
        private bool _append;
        private Encoding _encoding;
        private bool disposedValue;
        private readonly string mutexName = "MutithreadingMultipartWriteStream_Mutex";
        private Mutex mutex;

        public PartialStreamWriter(int MaxRows, string path, bool append, Encoding encoding)
        {
            if (MaxRows <= 0) throw new ArgumentOutOfRangeException("MaxRows", "MaxRows must be positive integer greater than 0");
            this.mutex = new Mutex(false, mutexName);
            this._maxRows = MaxRows;
            this._counter = 0;
            this._currentPart = 0;
            this._path = path;
            this._currentPath = path;
            this._append = append;
            this._encoding = encoding;
            this._streamWriter = TextWriter.Synchronized(new StreamWriter(path, append, encoding));
        }

        public virtual void WriteLine(string value)
        {
            mutex.WaitOne();
            if (_counter >= _maxRows)
            {
                _streamWriter.Flush();
                _currentPath = _path + $".part{_currentPart++.ToString("D4")}";
                OnNewPartStarted();
                _streamWriter = TextWriter.Synchronized(new StreamWriter(_currentPath, _append, _encoding));
                _counter = 0;
            }
            _streamWriter.WriteLine(value);
            _counter++;
            mutex.ReleaseMutex();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _streamWriter.Dispose();
                }
                disposedValue = true;
            }
        }
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        public delegate void NewPartEventHandler(object sender, NewPartStartedEventArgs e);

        public event NewPartEventHandler NewPartStarted;
        
        protected virtual void OnNewPartStarted()
        {
            NewPartStarted?.Invoke(this, new NewPartStartedEventArgs(_currentPath));
        }
    }

    public class NewPartStartedEventArgs : EventArgs
    {
        public NewPartStartedEventArgs(string newPartPath)
        {
            this.newPartPath = newPartPath;
        }

        public string newPartPath { get; }
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
            int SubsetPercentage = 50, 
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

            T[] ReturnValue = OriginalSet.ToArray();

            int NumberOfRecords = Math.Min(MinNumber, ReturnValue.Length * SubsetPercentage / 100);

            float[] ratios = new float[] { 
                (float)1 / 2, 
                (float)1 / 3, 
                (float)2 / 3, 
                (float)1 / 5, 
                (float)2 / 5, 
                (float)3 / 5, 
                (float)4 / 5, 
                (float)3 / 7, 
                (float)5 / 7,
                (float)6 / 7,
                (float)5 / 11,
                (float)6 / 11,
                (float)10 / 11};
            KeyValuePair<float, float>[] ratiosDeltas = new KeyValuePair<float, float>[ratios.Length];
            //Shuffle and take an half till the number is less then the required one
            while (ReturnValue.Length - 1 > NumberOfRecords)
            {
                for (int i = 0; i < ratios.Length; i++)
                {
                    ratiosDeltas[i] = new KeyValuePair<float, float>(ratios[i], (float)NumberOfRecords - (ReturnValue.Length * ratios[i]));
                }

                //float bestRatio = ratiosDeltas.Where(l => Math.Abs(l.Value) == ratiosDeltas.ToList().Min(t => Math.Abs(t.Value))).First().Key;
                //ReturnValue = Quarter(Shuffle(ReturnValue), bestRatio) as T[];
                ReturnValue = Quarter(Shuffle(ReturnValue), Math.Min((double)SubsetPercentage / 100, (double)MinNumber / ReturnValue.Length)) as T[];
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
            List<T> lt = OriginalSubset.ToList<T>();
            bool[] map = new bool[lt.Count];
            T[] arr = new T[lt.Count];
            int j = 0;                      //An index
            byte[] RandomNumber = new byte[4 * lt.Count];
            rngCsp.GetBytes(RandomNumber);
            while (j < lt.Count)
            {
                int NumberToPick = (int)(BitConverter.ToUInt32(RandomNumber, 0 + j * 4) % lt.Count);
                while (map[NumberToPick]) if (++NumberToPick >= lt.Count) NumberToPick = 0;
                map[NumberToPick] = true;
                arr[j++] = lt[NumberToPick];
            }
            rngCsp.Dispose();
            return arr;
        }

        /// <summary>
        /// Performs a quartering (selecting only even parts of the subset divided in four) 
        /// </summary>
        /// <param name="OriginalSubset"></param>
        /// <returns></returns>
        public static IEnumerable<T> Quarter(IEnumerable<T> OriginalSubset, double ratio = (double)1 / 2)
        {
            List<T> lt = OriginalSubset.ToList<T>();
            T[] res = new T[(int)(lt.Count * ratio)];
            res[0] = lt[0];
            for (int i = 1; i < (int)(lt.Count * ratio); i++)
            {
                res[i] = lt[(int)(i / ratio - 1)];
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