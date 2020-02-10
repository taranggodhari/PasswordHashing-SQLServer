using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.Data;
using System.Configuration;
using System.IO;
using System.Diagnostics;
using PassHash;
using Newtonsoft.Json;

namespace Passhash
{
    class Program
    {
        static void Main(string[] args)
        {
            HashPasswords();
            //VerifyPassword();
            Console.ReadLine();
        }

        public static void HashPasswords()
        {
            //Create object of Stopwatch 
            Stopwatch stopwatch = Stopwatch.StartNew();

            //Pulling data and hashing passwords in datatable
            stopwatch.Start();
            var datatable = GetHashedDataTable(GetSourceConnectionString(), "dbo.tblUsers");
            stopwatch.Stop();
            Console.WriteLine("Time taken to update Datatable: {0} \n", stopwatch.Elapsed);

            stopwatch.Reset();


            stopwatch.Start();
            //Upserting Table(Update & Insert)
            UpsertDatatable(GetDestinationConnectionString(), datatable);
            //Starting Bulk Copy(insert only)
            //BulkCopyPasswords(datatable, GetDestinationConnectionString(), "dbo.tblUsers");
            stopwatch.Stop();
            Console.WriteLine("Time taken to Bulk Copy: {0}", stopwatch.Elapsed);
            Console.WriteLine(">>>> Done Hashing Passwords");
        }

        //Get Rows and Hash Datatable > estimated 4 hrs
        public static DataTable GetHashedDataTable(string connectionString, string sourceTableName)
        {
            var datatable = new DataTable();
            int count = 0;

            using (SqlConnection connSelect = new SqlConnection(connectionString))
            {
                connSelect.Open();
                var selectCommand = string.Format("SELECT TOP 100 * FROM {0}", sourceTableName);
                SqlCommand cmd = new SqlCommand(selectCommand, connSelect);

                // Load Datatable with all the rows from tblUsers
                datatable.Load(cmd.ExecuteReader());
                connSelect.Close();
            }

            Console.WriteLine(">>>>Started Password Hashing");
            //Hash all passwords in the datatable
            foreach (DataRow dr in datatable.Rows)
            {
                dr["PassHash"] = PasswordHashing.HashPassword(dr["Password"].ToString());
                Console.Write("\rHashed {0} rows   ", ++count);
            }
            Console.WriteLine("Total Rows updated: {0}", count);

            return datatable;
        }

        //Bulk Copy the datatable to destination database
        public static void BulkCopyPasswords(DataTable dataTable, string destinationConnection, string destTableName)
        {
            Console.WriteLine(">>>> Starting Bulk Copy");
            using (SqlBulkCopy bulk = new SqlBulkCopy(destinationConnection))
            {
                bulk.DestinationTableName = destTableName;
                bulk.WriteToServer(dataTable);
            }
        }

        //Upsert using Stored Procedure
        public static void UpsertDatatable(string connectionString, DataTable dataTable)
        {
            int rowCount = 0;
            using (SqlConnection con = new SqlConnection(connectionString))
            {
                using (SqlCommand updatecmd = new SqlCommand("updateUsers", con))
                {
                    updatecmd.CommandType = CommandType.StoredProcedure;
                    updatecmd.Parameters.AddWithValue("@tblUser", dataTable);
                    con.Open();
                    updatecmd.ExecuteNonQuery();
                    con.Close();
                }
            }
            Console.WriteLine(">>>> Rows Upserted");
        }

        //Compares Plain text and Hashed Password
        public static bool VerifyPassword()
        {
            var isValid = false;
            string connectionString = GetDestinationConnectionString();
            SqlConnection connSelect = new SqlConnection(connectionString);
            connSelect.Open();

            SqlCommand cmd = new SqlCommand("Select * from dbo.tblUsers", connSelect);
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                string output = "";
                //read reader
                int count = 0;
                while (reader.Read())
                {

                    isValid = PasswordHashing.ValidatePassword(reader[1].ToString(), reader[2].ToString());

                    output += "Password Match for UserID: " + reader[0] + " is " + isValid + "\n";
                    Console.Write("\rCount is: {0} rows   ", ++count);
                }
                OutputToFile.ToText(output);
                connSelect.Close();
            }
            return isValid;
        }

        //Source and Destination Connection Strings
        private static string GetSourceConnectionString()
        {
            return ConfigurationManager.ConnectionStrings["internetUsersContext"].ConnectionString;
        }
        private static string GetDestinationConnectionString()
        {
            return ConfigurationManager.ConnectionStrings["internetUsersLocal"].ConnectionString;
        }
    }
}

