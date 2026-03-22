# HTB Luck Dice — Full Writeup

**Platform:** Hack The Box
**Difficulty:** Easy
**OS:** Linux

---

## Overview

Luck Dice is an interactive challenge that tests automation and logic. Upon connecting to the target service, the user is invited to participate in a "Dice Arena" game. The rules are straightforward: multiple human players roll several dice each round, and the player with the highest total score wins. In the event of a draw, the player who rolled the last dice (the highest-indexed player among those tied) is declared the winner. The challenge requires winning 100 consecutive rounds to obtain the flag.

**Full chain:**
```
Identify scoring and tie-breaking logic
  -> Automate round solutions via Python script (100 rounds)
    -> Obtain Flag
```

---

## Reconnaissance

### Service Identification

Connecting to the provided IP and port reveals a custom text-based game:

```bash
nc 154.57.164.67 30387
```

Output:
```
WELCOME TO THE DICE ARENA ...
     ____             
    /" .\\    _____   
   /: \\___\\  / .  /\\  
   " / . / /____/..\\ 
    \\/___/  "  "\\  / 
             "__"\\/  
Welcome my fellow bot!
I will need your help!
We are taksed to keep the score on this human game.
The game is simple!
Let's go over the rules...
1. On each round, each human player roles several dice.
2. The outcome of the dice is added to the player's score.
3. The round is won by the player with the highest overall score.
4. If there is a draw, the player who rolled the last dice wins the round.
```

---

## Exploitation

### Automation

Since the game requires solving 100 rounds with increasing numbers of dice and players, manual calculation is impractical. A Python script was developed to parse the output, calculate the winners, and send the correct responses.

#### Interaction Script

The script uses regular expressions to extract the dice rolls for each player and implements the tie-breaking logic.

```python
import socket
import re

def interact():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(("154.57.164.67", 30387))
    
    def receive_until(prompt):
        data = b""
        while prompt.encode() not in data:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        return data.decode()

    # Step 1: Handle Intro
    receive_until("> ")
    s.send(b"1\n")

    # Step 2: Handle Rounds
    while True:
        output = receive_until("> ")
        if "HTB{" in output:
            print(output) # Print flag
            break
            
        if "Who wins this round?" in output:
            players = re.findall(r"Player (\d+): ([\d ]+)", output)
            max_score = -1
            winner = -1
            
            for p_id_str, rolls_str in players:
                p_id = int(p_id_str)
                rolls = [int(x) for x in rolls_str.split()]
                score = sum(rolls)
                
                # Rule: highest score wins. 
                # Rule: last player wins a draw (>= handles this).
                if score >= max_score:
                    max_score = score
                    winner = p_id
            
            s.send(f"{winner}\n".encode())
        else:
            if not output: break

    s.close()

if __name__ == "__main__":
    interact()
```

### Flag Extraction

After successfully completing 100 rounds, the service provides the flag:

**Flag:** `HTB{r0LL1ng-1n-t43_D33P-b0t_n3T-cRe4t10n}`

---
