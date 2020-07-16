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
        /*
            - 1) Clone table tblUsers into temp datatable and hash all the passwords (Time taken > 3hrs)
            - 2) Once done, clone tblUsers (the second pass, now several hours later) into new Datatable
            - 3) Compare hashed datatable(step 1) and cloned datatable(step 2) for
                    a) new users (UserIDs in clonedDatatable not in hashedDatable) 
                    b) records where the plain text password in cloned datatable is different than in hashed datatable (so the user changed their password).  
            - 4) bulk update tblUsers with the reverified/hased datatable
        */

        //private static string sourceConnection = ConfigurationManager.ConnectionStrings["internetUsersContext"].ConnectionString;
        private static string destinationConnection = ConfigurationManager.ConnectionStrings["internetUsersLocal"].ConnectionString;

        static void Main(string[] args)
        {
            Stopwatch sw = Stopwatch.StartNew();
            sw.Start();

            string tblUsers = "dbo.tblUsers";

            //clone tblUsers to datatable and hash passowords
            DataTable hashedDatatable = HashPasswords(tblUsers);

            //clone tblUsers to datatable with 3 columns
            string columns = "[UserID], [Password], [PassHash]";
            DataTable clonedDatatable = GetTableAsDatatable(tblUsers, columns);

            //compare tables for new or updated users/passwords
            DataTable finalDatatable = ReverifyPassword(hashedDatatable, clonedDatatable);

            //Update tblUsers using Datatable
            UpdateTable(finalDatatable);
            
            sw.Stop();
            Console.WriteLine("Total Time Taken: " + sw.Elapsed);
            //Verify Password column with PassHash column
            VerifyPassword();

            Console.ReadLine();
        }

        public static DataTable HashPasswords(string sourceTable)
        {
            int count = 0;

            //Pulling data and hashing passwords in datatable
            string columns = "[UserID], [Password], [PassHash]";
            DataTable datatable = GetTableAsDatatable(sourceTable, columns);

            //Hash all the passwords in datatable
            Console.WriteLine(">>>> Started Password Hashing");
            foreach (DataRow dr in datatable.Rows)
            {
                dr["PassHash"] = PasswordHashing.HashPassword(dr["Password"].ToString());
                Console.Write("\rHashed {0} rows   ", ++count);
            }
            Console.WriteLine();

            return datatable;
        }

        //Compares Plain text and Hashed Password
        public static bool VerifyPassword()
        {
            var isValid = false;
            string connectionString = destinationConnection;
            SqlConnection connSelect = new SqlConnection(connectionString);
            connSelect.Open();

            SqlCommand cmd = new SqlCommand("Select [UserID], [Password], [PassHash] from dbo.tblUsers", connSelect);
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                string output = "";
                int count = 0;
                while (reader.Read())
                {
                    if (reader[2] != null && !String.IsNullOrEmpty(reader[2].ToString()))
                    {
                        isValid = PasswordHashing.ValidatePassword(reader[1].ToString(), reader[2].ToString());
                        output += "Password Match for UserID: " + reader[0] + " is " + isValid + "\n";
                        Console.Write("\rValidated {0} rows   ", ++count);
                    }
                }
                OutputToFile.ToText(output, "passwordVerification");
                connSelect.Close();
            }
            return isValid;
        }

        public static DataTable GetTableAsDatatable(string tableName, string columns = "*")
        {
            DataTable datatable = new DataTable();

            using (SqlConnection connSelect = new SqlConnection(destinationConnection))
            {
                connSelect.Open();
                var selectCommand = string.Format("SELECT {1} FROM {0}", tableName, columns);
                SqlCommand cmd = new SqlCommand(selectCommand, connSelect);
                datatable.Load(cmd.ExecuteReader());
                connSelect.Close();
            }
            //update few passwords on cloned dt for testing
            //if (columns.Contains("101"))
            //{
            //    datatable.Rows[1][1] = "NewPasswd";
            //    datatable.Rows[5][1] = "NewP@ssW''or";
            //}
            return datatable;
        }

        //reverify and hash the updated/new passwords
        public static DataTable ReverifyPassword(DataTable sourceDatatable, DataTable destinationDatatable)
        {
            int count = 0;

            //rehash updated password
            foreach (DataRow item in sourceDatatable.Rows)
            {
                if (!item.IsNull("Password") && !item.IsNull("UserID"))
                {
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
            return sourceDatatable;
        }

        //Update Table tblUsers
        public static void UpdateTable(DataTable datatable)
        {
            using (SqlConnection conn = new SqlConnection(destinationConnection))
            {
                using (SqlCommand cmd = new SqlCommand("", conn))
                {
                    try
                    {
                        conn.Open();
                        // Creating temp table with same defination as tblUsers with 3 columns only
                        cmd.CommandText = "SELECT TOP 0 [UserID], [Password], [PassHash] into #TmpTable from [dbo].[tblUsers]";
                        cmd.ExecuteNonQuery();
                        // Bulk insert into temp table
                        using (var bulkcopy = new SqlBulkCopy(conn))
                        {
                            bulkcopy.DestinationTableName = "#TmpTable";
                            bulkcopy.WriteToServer(datatable);
                            bulkcopy.Close();
                        }

                        // Updating tblUsers, and dropping temp table
                        cmd.CommandText = "UPDATE Users SET Users.Password = Temp.Password, Users.PassHash = Temp.PassHash " +
                                            "FROM tblUsers Users " +
                                            "INNER JOIN #TmpTable Temp ON (Temp.UserID = Users.UserID) " +
                                            "DROP TABLE #TmpTable";
                        cmd.ExecuteNonQuery();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error : " + ex.Message);
                        string error = "\nMessage: " + ex.Message + "\n";
                        error += "Inner Exception: " + ex.InnerException + "\n";
                        error += "StackTrace: " + ex.StackTrace;
                        OutputToFile.ToText(error, "ExceptionLog");
                    }
                    finally
                    {
                        conn.Close();
                    }
                }
            }
            Console.WriteLine(">>>> Updated tblUsers with Hashed Passwords <<<<");
        }
    }
}

