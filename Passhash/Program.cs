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
        /***
            - 1) Hash passwords and copy all records from tblUsers (over 100K) into temp table (say 'tblUsersTemp')
            - 2) once done, again copy all records from tblUsers (the second pass, now several hours later) into another temp table 'tblUsersTemp2' and compare with records in tblUsersTemp
            - 3) update PassHash in tblUserTemp for 
                    a) new users (UserIDs in tblUserTemp2 not in tblUserTemp) 
                    b) records where the plain text password in tblUsersTemp2 is different than in tblUsersTemp (so the user changed their password).  
            - 4) bulk update tblUsers with tblUserTemp
        ***/

        //private static string sourceConnection = ConfigurationManager.ConnectionStrings["internetUsersContext"].ConnectionString;
        private static string destinationConnection = ConfigurationManager.ConnectionStrings["internetUsersLocal"].ConnectionString;

        static void Main(string[] args)
        {
            string tblUsers = "dbo.tblUsers",
                   tblUsersTemp = "dbo.tblUsersTemp",
                   tblUsersTemp2 = "dbo.tblUsersTemp2";

            
            //clone tblUsers to tblUsersTemp and hash passoword on tblUsersTemp
            HashPasswords(tblUsers, tblUsersTemp);
            
            //clone tblUsers to tblUsersTemp2
            CloneTable(tblUsers, tblUsersTemp2);
            
            //compare tables for new or updated users/passwords
            DataTable finalDT = ReverifyPassword(tblUsersTemp, tblUsersTemp2);
            
            //Upsert Datatable to tblUsers
            UpsertDatatable(destinationConnection, finalDT);

            //Verify Password column with PassHash column
            //VerifyPassword();
            
            Console.ReadLine();
        }

        public static void HashPasswords(string sourceTable, string destinationTable)
        {
            //Create object of Stopwatch 
            Stopwatch stopwatch = Stopwatch.StartNew();

            //Pulling data and hashing passwords in datatable
            stopwatch.Start();
            var datatable = GetHashedDataTable(destinationConnection, sourceTable);
            stopwatch.Stop();
            Console.WriteLine("Time taken to update Datatable: {0} \n", stopwatch.Elapsed);
            stopwatch.Reset();

            //Starting Bulk Copy(insert only)
            stopwatch.Start();
            Console.WriteLine(">>>> Starting Bulk Copy");
            BulkCopyPasswords(datatable, destinationConnection, destinationTable);
            stopwatch.Stop();
            Console.WriteLine(">>>> Bulk copy from [" + sourceTable + "] To [" + destinationTable + "] Completed Successfully");
            Console.WriteLine("Time taken to Bulk Copy: {0}", stopwatch.Elapsed);

            Console.WriteLine(">>>> Done Hashing Passwords");
        }

        //Get Rows and Hash Datatable > estimated 4 hrs
        public static DataTable GetHashedDataTable(string connectionString, string sourceTableName)
        {
            int count = 0;

            // Load Datatable with all the rows from tblUsers
            DataTable datatable = GetTableAsDatatable(sourceTableName);

            //Hash all the passwords in datatable
            Console.WriteLine(">>>>Started Password Hashing");
            foreach (DataRow dr in datatable.Rows)
            {
                dr["PassHash"] = PasswordHashing.HashPassword(dr["Password"].ToString());
                Console.Write("\rHashed {0} rows   ", ++count);
            }
            Console.WriteLine("Total Rows updated: {0}", count);

            return datatable;
        }

        //Bulk Copy the datatable to destination database table
        public static void BulkCopyPasswords(DataTable dataTable, string destinationConnection, string destTableName)
        {
            using (SqlBulkCopy bulk = new SqlBulkCopy(destinationConnection))
            {
                bulk.DestinationTableName = destTableName;
                bulk.WriteToServer(dataTable);
            }
        }

        //Upsert to tblUsers using the Stored Procedure 
        public static void UpsertDatatable(string connectionString, DataTable dataTable)
        {
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
            string connectionString = destinationConnection;
            SqlConnection connSelect = new SqlConnection(connectionString);
            connSelect.Open();

            SqlCommand cmd = new SqlCommand("Select * from dbo.tblUsers", connSelect);
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                string output = "";
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

        public static void CloneTable(string sourceTable, string destinationTable)
        {
            DataTable datatable = GetTableAsDatatable(sourceTable);
            
            using (SqlBulkCopy bulk = new SqlBulkCopy(destinationConnection))
            {
                bulk.DestinationTableName = destinationTable;
                bulk.WriteToServer(datatable);
            }

            Console.WriteLine(">>>> Bulk copy from [" + sourceTable + "] To [" + destinationTable + "] Completed Successfully");
        }

        public static DataTable GetTableAsDatatable(string tableName) {
            DataTable datatable = new DataTable();

            using (SqlConnection connSelect = new SqlConnection(destinationConnection))
            {
                connSelect.Open();
                var selectCommand = string.Format("SELECT * FROM {0}", tableName);
                SqlCommand cmd = new SqlCommand(selectCommand, connSelect);
                datatable.Load(cmd.ExecuteReader());
                connSelect.Close();
            }

            return datatable;
        }

        public static DataTable ReverifyPassword(string sourceTableName, string destinationTableName)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            var sourceDatatable = GetTableAsDatatable(sourceTableName);
            var destinationDatatable = GetTableAsDatatable(destinationTableName);
            int count = 0;

            stopwatch.Start();
            //rehash updated password
            Console.WriteLine(">>>> Rehashing the updated passwords");
            foreach (DataRow item in sourceDatatable.Rows)
            {
                if (!item.IsNull("Password") && !item.IsNull("UserID")) {
                    string userID = item["UserID"].ToString();
                    string password = item["Password"].ToString();
                    password = password.Replace("'", "''");
             
                    string selectQ = String.Format("UserID = '{0}' AND Password <> '{1}'", userID, password);
                    DataRow pwdRow = destinationDatatable.Select(selectQ).FirstOrDefault();
                    
                    if (pwdRow != null)
                    {
                        item["Password"] = pwdRow["Password"];
                        item["PassHash"] = PasswordHashing.HashPassword(pwdRow["Password"].ToString());
                        ++count;
                    }
                }
            }
            Console.WriteLine(">>>> Completed Rehashing [" + count + "] updated passwords");

            //hash passwords for new users
            count = 0;
            Console.WriteLine(">>>> Rehashing passwords for new users");
            if (destinationDatatable.Rows.Count > sourceDatatable.Rows.Count)
            {
                foreach (DataRow drDest in destinationDatatable.Rows)
                {
                    DataRow[] foundUsers = sourceDatatable.Select("UserID = '" + drDest["UserID"] + "'");
                    if (foundUsers.Length == 0)
                    {
                        drDest["PassHash"] = PasswordHashing.HashPassword(drDest["Password"].ToString());
                        sourceDatatable.ImportRow(drDest);
                        ++count;
                    }
                }
                Console.WriteLine(">>>> Completed Rehashing [" + count + "] new user's passwords");
            }
            stopwatch.Stop();
            Console.WriteLine("Time taken to reverify passwords: {0} \n", stopwatch.Elapsed);
            return sourceDatatable;
        }
    }
}

