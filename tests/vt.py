"""Tiny VT100 screen model: enough of what ncurses emits to reconstruct the visible text in TUI tests."""
# Minimal VT100 screen model: enough of what ncurses emits for xterm to reconstruct the visible text.
import re
class Screen:
    def __init__(s, rows, cols): s.r, s.c = rows, cols; s.g = [[" "] * cols for _ in range(rows)]; s.y = s.x = 0; s.top, s.bot = 0, rows - 1; s.last = " "
    def feed(s, data):
        i = 0
        while i < len(data):
            ch = data[i]
            if ch == "\x1b":
                m = re.match(r"\x1b\[([?>]?)([0-9;]*)([A-Za-z@`])", data[i:])
                if m:
                    s.csi(m.group(1), [int(p) if p else 0 for p in m.group(2).split(";")] if m.group(2) else [], m.group(3)); i += m.end(); continue
                m = re.match(r"\x1b(\][^\x07]*\x07|[()][A-Z0-9]|[=>78M])", data[i:])
                if m:
                    if m.group(1) == "M": s.y = max(0, s.y - 1)
                    i += m.end(); continue
                i += 1; continue
            if ch == "\r": s.x = 0
            elif ch == "\n": s.lf()
            elif ch == "\b": s.x = max(0, s.x - 1)
            elif ch >= " ":
                if s.x >= s.c: s.x = 0; s.lf()
                s.g[s.y][s.x] = ch; s.last = ch; s.x += 1
            i += 1
    def lf(s):
        if s.y == s.bot: s.g.pop(s.top); s.g.insert(s.bot, [" "] * s.c)
        else: s.y = min(s.r - 1, s.y + 1)
    def csi(s, priv, p, f):
        n = (p[0] if p and p[0] else 1)
        if priv: return
        if f in "Hf": s.y = min(s.r - 1, (p[0] if p and p[0] else 1) - 1); s.x = min(s.c - 1, (p[1] if len(p) > 1 and p[1] else 1) - 1)
        elif f == "A": s.y = max(0, s.y - n)
        elif f == "B": s.y = min(s.r - 1, s.y + n)
        elif f == "C": s.x = min(s.c - 1, s.x + n)
        elif f == "D": s.x = max(0, s.x - n)
        elif f in "G`": s.x = min(s.c - 1, n - 1)
        elif f == "d": s.y = min(s.r - 1, n - 1)
        elif f == "b":
            for _ in range(n):
                if s.x < s.c: s.g[s.y][s.x] = s.last; s.x += 1
        elif f == "X":
            for k in range(s.x, min(s.c, s.x + n)): s.g[s.y][k] = " "
        elif f == "K":
            m = p[0] if p else 0; rng = range(s.x, s.c) if m == 0 else range(0, s.x + 1) if m == 1 else range(s.c)
            for k in rng: s.g[s.y][k] = " "
        elif f == "J":
            m = p[0] if p else 0
            if m == 0: s.csi("", [0], "K"); rows = range(s.y + 1, s.r)
            elif m == 1: rows = range(0, s.y)
            else: rows = range(s.r)
            for y in rows: s.g[y] = [" "] * s.c
        elif f == "r": s.top = (p[0] if p and p[0] else 1) - 1; s.bot = (p[1] if len(p) > 1 and p[1] else s.r) - 1; s.y = s.x = 0
        elif f == "S":
            for _ in range(n): s.g.pop(s.top); s.g.insert(s.bot, [" "] * s.c)
        elif f == "T":
            for _ in range(n): s.g.pop(s.bot); s.g.insert(s.top, [" "] * s.c)
        elif f == "@":
            row = s.g[s.y]; row[s.x:s.x] = [" "] * n; del row[s.c:]
        elif f == "P":
            row = s.g[s.y]; del row[s.x:s.x + n]; row += [" "] * (s.c - len(row))
        elif f == "L":
            for _ in range(n): s.g.insert(s.y, [" "] * s.c); s.g.pop(s.bot + 1)
        elif f == "M":
            for _ in range(n): s.g.pop(s.y); s.g.insert(s.bot, [" "] * s.c)
    def text(s): return "\n".join("".join(r).rstrip() for r in s.g)
