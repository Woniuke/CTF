# GWoC
1. There are two TLS callback functions , the first one contains int3 , You can patch it.
2. It will create four threads by same function , according the blog as below , http://blog.rewolf.pl/blog/?p=102 , we can know it's running x64 code in x32 process.
3. You can debug it  by WinDBG x64!!  It's the only debugger can disassmble the code correctly which I have ever tried.
4. Open it by IDA pro x64 , Press Alt+S , Choose x64 mode to analysis x64 code . Then open it by IDA pro x32 to analysis x32 code.

# gestapo
1. We can get python source code by Easy Python Decompiler.
2. Analysis the python code , We can know it's based on Shamir's Secret Sharing . The secret was divided into 5 pieces . So the equation as below, a0 is secret.

<center><img src="https://latex.codecogs.com/gif.latex?f(x)&space;=&space;a_0&space;&plus;&space;a_1x&space;&plus;&space;a_2x^2&space;&plus;&space;a_3x^3&space;&plus;&space;a_4x^4" title="f(x) = a_0 + a_1x + a_2x^2 + a_3x^3 + a_4x^4" /></center>

3. We can find that it's using same<img src="https://latex.codecogs.com/gif.latex?a_1,a_2,a_3,a_4" title="a_1,a_2,a_3,a_4" /> for each character in string when encrypting . IT IS THE MAIN WEAKNESS.
4. We just get four parts . We can calculate <img src="https://latex.codecogs.com/gif.latex?a_1,a_2,a_3,a_4" title="a_1,a_2,a_3,a_4" /> when we having at least five different parts according to the equation . But we konw the first word in plaintext is 'flag' , so we can try $$ (x_5,y_5) $$ to solve the equation when we get the first character is 'f' , Then try to decrypt other characters by <img src="https://latex.codecogs.com/gif.latex?a_1,a_2,a_3,a_4" title="a_1,a_2,a_3,a_4" />