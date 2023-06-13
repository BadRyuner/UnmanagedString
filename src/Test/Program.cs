using System.Diagnostics;

var timer = new Stopwatch();
timer.Start();
for(int i = 0; i < 100000; i++)
	Console.WriteLine("Some big text, aaaaaaaaaaaaa, brrrrrrrrrrrrrrr, allocations is too slooooooooooooow. 11111111111111111111111, AAAAAAAAAAAA, 222222222");
timer.Stop();
Console.WriteLine(timer.ElapsedMilliseconds);

var getstr = () => "ololo";
var str = getstr();
Console.WriteLine(str);
unsafe
{
	fixed(char* c = str)
		c[0] = 'a';
}
Console.WriteLine(str);
str = getstr();
Console.WriteLine(str);