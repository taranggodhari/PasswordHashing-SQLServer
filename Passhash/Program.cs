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
        //private static string sourceConnection = ConfigurationManager.ConnectionStrings["internetUsersContext"].ConnectionString;
        private static string destinationConnection = ConfigurationManager.ConnectionStrings["internetUsersLocal"].ConnectionString;

        static void Main(string[] args)
        {
            //hash passwords 
            FirstPass();

            //verify and hash new/updated passwords
            SecondPass();

            //update tblUsers 
            FinalPass();

            //verify plain text and hashed passwords
            VerifyPassword();

            Console.ReadLine();
        }
        public static void FirstPass()
        {
            Console.WriteLine("## Starting First Pass ##");
            int BatchSize = 100;
            int rowCount = 0;
            DataTable datatable = new DataTable();

            using (SqlConnection conn = new SqlConnection(destinationConnection))
            {
                conn.Open();

                //create table tblUserTemp if it doesn't exists
                string queryExist = @"IF NOT EXISTS(SELECT * FROM internetusers.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = N'dbo' AND TABLE_NAME = N'tblUsersTemp')" +
                                        "CREATE TABLE [dbo].[tblUsersTemp] (UserID int NOT NULL, Password varchar(50) NULL, PassHash varchar(120) NULL);";
                using (SqlCommand command = new SqlCommand(queryExist, conn))
                {
                    command.ExecuteNonQuery();
                }

                //select all the records from tblUsers which are not hashed or with invalid passwords in tblUsersTemp
                string querySelect = @"SELECT U.[UserID], U.[Password], U.[PassHash] 
                                        FROM [internetusers].[dbo].[tblUsers] U 
                                        LEFT JOIN [internetusers].[dbo].[tblUsersTemp] UT 
                                        ON U.UserID = UT.UserID 
                                        WHERE U.Password <> UT.Password OR UT.PassHash IS NULL";
                SqlCommand cmd = new SqlCommand(querySelect, conn);
                datatable.Load(cmd.ExecuteReader());
                rowCount = HashAndUpsertTable(datatable, BatchSize);
            }
            Console.WriteLine(">>>> Total Rows Updated: " + rowCount);
            Console.WriteLine("## First Pass Completed ##");
        }

        //reverify and hash the updated/new passwords
        public static void SecondPass()
        {
            Console.WriteLine("\n## Starting Second Pass ##");
            int BatchSize = 100;
            int rowCount = 0;
            using (SqlConnection conn = new SqlConnection(destinationConnection))
            {
                conn.Open();
                DataTable datatable = new DataTable();
                //Clone and copy rows from tblUsers into tblUsersTemp2
                var selectIntoCommand = @"IF EXISTS(SELECT * FROM internetusers.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = N'dbo' AND TABLE_NAME = N'tblUsersTemp2')" +
	                                        "BEGIN " +
	                                            "DROP TABLE [internetusers].[dbo].[tblUsersTemp2]; " +
	                                            "SELECT UserID, Password, PassHash INTO [internetusers].[dbo].[tblUsersTemp2] FROM [internetusers].[dbo].[tblUsers]; " +
	                                        "END " +
                                          "ELSE " +
	                                        "BEGIN " +
	                                            "(SELECT UserID, Password, PassHash INTO [internetusers].[dbo].[tblUsersTemp2] FROM [internetusers].[dbo].[tblUsers]); " +
	                                        "END";
                SqlCommand selectCommand = new SqlCommand(selectIntoCommand, conn);
                selectCommand.ExecuteNonQuery();

                //Compare table tblUsersTemp and tblUsersTemp2 for diffrent Password
                string compareQuery = @"SELECT UT2.UserID, UT2.Password, UT2.PassHash from tblUsersTemp2 UT2 " +
                                        "LEFT JOIN tblUsersTemp UT ON (UT2.UserID = UT.UserID) " +
                                        "WHERE UT2.Password <> UT.Password OR UT.PassHash IS NULL";
                
                SqlCommand command = new SqlCommand(compareQuery, conn);
                datatable.Load(command.ExecuteReader());
                rowCount = HashAndUpsertTable(datatable, BatchSize);
                Console.WriteLine(">>>> Total New or Updated Rows : " + rowCount);
            }
            Console.WriteLine("## Second Pass Completed ##");
        }

        //Update Table tblUsers after passwords are hashed in tblUsersTemp
        public static void FinalPass()
        {
            Console.WriteLine("\n## Starting Final Pass ##");
            using (SqlConnection conn = new SqlConnection(destinationConnection))
            {
                using (SqlCommand cmd = new SqlCommand("", conn))
                {
                    try
                    {
                        conn.Open();
                        // Updating tblUsers, and dropping temp table
                        cmd.CommandText = "UPDATE Users SET Users.Password = Temp.Password, Users.PassHash = Temp.PassHash " +
                                            "FROM [internetusers].[dbo].[tblUsers] Users " +
                                            "INNER JOIN [internetusers].[dbo].[tblUsersTemp] Temp ON (Temp.UserID = Users.UserID)";
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
            Console.WriteLine("## Final Pass Completed ##");
        }

        //Compares Plain text and Hashed Password
        public static bool VerifyPassword()
        {
            Console.WriteLine("\n## Started Verification Process ##");
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
                System.Diagnostics.Process.Start(Path.Combine(Directory.GetCurrentDirectory(), @"passwordVerification.txt"));
   
                connSelect.Close();
            }
            Console.WriteLine("\n## Verification Process Logged into passwordVerification.txt ##");
            return isValid;
        }

        public static int HashAndUpsertTable(DataTable datatable, int BatchSize)
        {
            int rowCount = 0;
            //clones the current datatable's schema and constraints into new datatable.
            DataTable copyDatatable = datatable.Clone();

            foreach (DataRow dr in datatable.Rows)
            {
                //Hash Passwords
                dr["PassHash"] = PasswordHashing.HashPassword(dr["Password"].ToString());

                copyDatatable.ImportRow(dr); // Import current row to cloned datatable

                //Upsert the datatable when the cloned datatable size is equal to batchsize
                if (copyDatatable.Rows.Count == BatchSize)
                {
                    rowCount += UpsertDatatable(copyDatatable);
                    Console.WriteLine(">>>> Updated: " + rowCount + " Rows");
                    copyDatatable = datatable.Clone(); //clears and clone the datatable
                }
            }
            //Upsert rest of the hashed datarows
            if (copyDatatable.Rows.Count > 0)
            {
                rowCount += UpsertDatatable(copyDatatable);
                Console.WriteLine(">>>> Updated: " + rowCount + " Rows");
            }
            return rowCount;
        }

        //using stored procedure to update or insert into table; returns number of rows upserted.
        public static int UpsertDatatable(DataTable datatable)
        {
            int rowsUpserted = 0;
            using (SqlConnection con = new SqlConnection(destinationConnection))
            {
                using (SqlCommand updatecmd = new SqlCommand("updateUsers", con))
                {
                    updatecmd.CommandType = CommandType.StoredProcedure;
                    updatecmd.Parameters.AddWithValue("@tblUser", datatable);
                    con.Open();
                    rowsUpserted = updatecmd.ExecuteNonQuery();
                    con.Close();
                }
            }
            return rowsUpserted;
        }
    }
}

