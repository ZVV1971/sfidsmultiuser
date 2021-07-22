using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Oracle.ManagedDataAccess.Client;

namespace OracleConnectivityTest
{
    class Program
    {
        static void Main(string[] args)
        {
            using (OracleConnection oc = new OracleConnection())
            {
                oc.ConnectionString = "User ID=INFA_TDM_REFERENCE; Password=informatica; " +
                    "Data Source=(DESCRIPTION =(ADDRESS = (PROTOCOL = TCP)(HOST = ecsc00a08bfb.epam.com)(PORT = 1521))(CONNECT_DATA =(SERVER = DEDICATED)(SID=ORCL)));";
                oc.Open();
                int[] foos = new int[3] { 1, 2, 3 };
                string[] bars = new string[3] { "A", "B", "C" };
                OracleParameter[] pFoo = new OracleParameter[2];
                foreach (OracleParameter p in pFoo)
                {
                    p.OracleDbType = OracleDbType.Varchar2;
                    p.Value = foos;
                }
                OracleCommand ocmd = new OracleCommand("CREATE TABLE TEST_TABLE (ID VARCHAR2(1), TEST_FIELD VARCHAR2(1))", oc);
                ocmd.ExecuteNonQuery();
            }
        }
    }
}
