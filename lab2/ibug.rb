def func(n, a, b, c, d, e, f)
  var t, x, y
  _ = GETC()
  _ += -48
  _ += a
  _ += b
  _ += c
  _ += d
  _ += e
  _ += f
  t = _
  if n > 1
    _ = n + -1
    x = func(_, a, b, c, d, e, f)
    _ = n + -2
    y = func(_, a, b, c, d, e, f)
    _ = x + y
    _ += t
    _ += -1
    return
  else
    return t
  end
end

def main
  var n
  n = GETC()
  n += -48
  _ = func(n, 0, 0, 0, 0, 0, 0)
end

start main
