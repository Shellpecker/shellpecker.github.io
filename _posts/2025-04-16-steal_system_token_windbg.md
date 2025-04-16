---
title: "OSEE - Part 2 - Steal System Token using WinDbg"
categories: ["OSEE", "Exploit Development"]
tags: ["osee", "exploiting"]     # TAG names should always be lowercase
toc: false
---

## Introduction
The purpose of this post is to show you who token manipulation (or stealing, call it whatever you want) concerning kernel exploitaion works. Before we deep dive into the real exploitation of drivers I think it is
a good idea to understand how the theory of certain local privilege escalations work. In this case I want to demonstrate the idea of replacing the token of the system process with your own cmd.exe just by using WinDbg.
This is certainly no exploit, but it should give you a rough idea what some kernel exploits want to achieve.
So we start a normal `cmd.exe` and run `whoami`.

> Image of terminal here

Nothing new here. But in the end of this post we will see that the same command will print you the well known `NT AUTHORITY\SYSTEM`.


## Getting the EPROCESS of impotant processes
First of all you can get the eprocess of the system process with
```
!process 4 0

Searching for Process with Cid == 4
PROCESS ffff9d8df3691040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ae002  ObjectTable: ffffe788af259e80  HandleCount: 3261.
    Image: System
```
which gives you the value `ffff9d8df3691040`. This value will probably be different on your machine, so dont worry if you have a different output

```
!process 0 0 cmd.exe

PROCESS ffff9d8df6133080
    SessionId: none  Cid: 113c    Peb: 7a76b0b000  ParentCid: 1120
    DirBase: 179c53002  ObjectTable: ffffe788d50e4580  HandleCount:  80.
    Image: cmd.exe
```

and we get the EPROCESS `ffff9d8df6133080`.

## Locating the Token of processes
Now as we have the eprocesses of our desired processes we need to locate the pointer to the respective tokens of that processes.
As this offset may vary depending on your windows version there are 2 ways how you can look up the structe.
Using WinDbg:
```
dt _eprocess
```
and then search for `Token` or by checking out the awesome [Vergilius Project](https://www.vergiliusproject.com/kernels) where you can check the offsets of
some structures depending on your version (e.g. E_PROCESS for [Windows 11 24H2 (2024 Update, Germanium)](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS)).

In both cases you should get a value of `0x248` for the value of token. Hence, the pointer to the Token structure.

We can check the value

## Overwriting the cmd.exe Token

```
eq [E_PROCESS of cmd.exe + 0x248] poi(EPROCESS_SYSTEM + 0x248)
```

now we can check if both values are identical with
```
db [EPROCESS_SYSTEM + 0x248] L8

db [EPROCESS_CMD.EXE + 0x248] L8
```

If so, you may continue running the debuggee with 
```
g
```
Now, if you run `whoami` in the same cmd.exe you should get a new result

> Image of cmd.exe after token manipulation

Congratulation you succesfully elevated your privileges of `cmd.exe` via WinDbg!



