---
title: "[corCTF 2022 - pwn] zigzag"
createdAt: 2022-08-08
type: 'Writeups'
tags: ["pwn"]
---

## Introduction

`zigzag` is a zig heap challenge I did during the [corCTF 2022](https://ctftime.org/event/1656) event. It was pretty exotic given we have to pwn a heap like challenge written in [zig](https://ziglang.org/). It is not using the C allocator but instead it uses the GeneralPurposeAllocator, which makes the challenge even more interesting. Find the tasks [here](https://github.com/ret2school/ctf/tree/master/2022/corCTF/pwn/zieg).