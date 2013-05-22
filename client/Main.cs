using System;

namespace client
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			Vulnerable v = new Vulnerable();

			string[] users = v.ListUsers();

			foreach (string user in users)
				Console.WriteLine(user);

			Console.WriteLine("Adding user blah:blah");
			v.AddUser("blah", "blah");

			users = v.ListUsers();

			foreach (string user in users)
				Console.WriteLine(user);

			Console.WriteLine("Deleteing user blah");
			bool worked = v.DeleteUser("blah");

			Console.WriteLine("Worked? " + worked);
		}
	}
}