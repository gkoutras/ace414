# ACE414 Assignment 6

In this assignment, a Bash script was implemented, that uses the Linux command `iptables` in order to create a simple adblocking mechanism.

---

## Network Scanning and Iptables

*note: The executable of the program is made by calling `chmod +x adblock.sh`.*  
*note: For it to run correctly, due to some commands that require root privileges, the script must be called as `sudo ./adblock.sh -[OPTIONS]`.*  
*note: Files produced must be manually deleted in between runs, otherwise previous results carry on.*

Some of the options for this script were implemented as follows:
- `-domains`: Through the use of `grep` and `readarray`, the domains that exist in both `domainNames.txt` and `domainNames2.txt`, were stored in array `arrSame` (9 same domains), and the ones that were unique were stored in array `arrDiff` (381 unique domains). In respective loops, throught the use of the `dig` command, the IP addresses of these domains were stored in `IPAddressesSame.txt` and `IPAddressesDifferent.txt`.
- `-ipssame`: The rules of `IPAddressesSame.txt` were added to the input chain through the use of `iptables` with option `-A INPUT` to append and `-j DROP` as the appropriate filter.
- `-ipsdiff`: The rules of `IPAddressesDifferent.txt` were added to the input chain through the use of `iptables` with option `-A INPUT` to append and `-j REJECT` as the appropriate filter.
- `-save`: Rules are saved to the `adblockRules` file specified with `iptables-save` command.
- `-load`: Rules are loaded from the `adblockRules` file specified with `iptables-restore` command.
- `-list`: Rules are listed and printed with `iptables -L` command.
- `-reset`: Through the use of `iptables` command with option `-D INPUT` rules stored to the input chain are deleted and the adblock is reset.

The adblocker is finally tested as follows:
1. By trying to access websites from the `IPAddressesSame.txt` list, which are filtered with `DROP` rules, and resulting to no reply being received from the browser.
2. By trying to access websites from the `IPAddressesDifferent.txt` list, which are filtered with `REJECT` rules, and resulting to no reply being received from the browser as well.
3. By trying to access websites with adds, resulting in the blocking of most of the website's adds, but some were more persistent. This could occur either because of the existence of adblocker detectors on some websites, or because the rules that must be configured need to be more complicated and specialised than the ones applied on this adblocker.
