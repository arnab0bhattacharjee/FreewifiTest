using System;

namespace MultiplyNumbers
{
    class Program
    {
        static void Main(string[] args)
        {
            int num1, num2, result;
            Console.Write("Enter the first number: ");
            num1 = Convert.ToInt32(Console.ReadLine());
            Console.Write("Enter the second number: ");
            num2 = Convert.ToInt32(Console.ReadLine());
            result = num1 * num2;
            Console.WriteLine("The product of " + num1 + " and " + num2 + " is " + result);
            Console.ReadKey();
        }
    }
}
