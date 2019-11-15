# SystemSecurity-DD2497
## Demonstrate that the program in /usr/games/overflow has a vulnerability due to a buffer overflow

By executing
``` c
./overflow attacker [address of authorized] | ./overflow victim
```
it's possible to achive an overflow attack where the `do_something()` function without providing the required password. The address of the *authorized* field can be obtained by first executing
``` c
./overflow victim
```
and noting the printed address.

The attacker function creates a special string long enough to fill the 10 bytes of *input* as well as the space from *input* to *message*. All space until *message* will be filled with A's, but at the proper position to fill *message* the address of *authorized* will be inserted.

The victim function then reads into *input* using gets(). When passed the special string created by the attacker this will accidentally also populate *message* with the adress of *authorized*, making message now point to *authorized*.

The password check in victim will fail as the string doesn't equal "pwd", so *authorized* will be set to 0. However, when using strcpy at line 29 to change the message to "Fail" this will not have the intended effect, but instead making *authorized* nonzero which means the `if(authorized)` check will pass and the `do_something()` function will be run.

## Demonstrate that ASLR counters the attack
This buffer overflow attack is only possible when the attacker knows the address of the *authorized* field, i.e. by noting the leaked address in victim-mode. The *authorized* field is declared inside the victim-function, which means it will end up somewhere on the stack segment. Without ASLR in place the address of *authorized* is the same every time the program is executed. 

If ASLR is implemented, the attacker needs to guess which address *authorized* will get in the second overflow call in 
``` c
./overflow attacker [address of authorized] | ./overflow victim
```
This makes the probability of a successful attack very low. 


## Contributions by authors
 * **Max Turpeinen** - Edited README
 * **Mona Lindgren** - Edited README
 * **Konstantinos Kalogiannis** - Edited README 
 * **Vera Blomkvist Karlsson** - Edited README
