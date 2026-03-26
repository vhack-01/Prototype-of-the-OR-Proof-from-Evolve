import sage.all as sg

from config.params import N, Q

# --------------------------------------------------------
#  Ring definitions
# --------------------------------------------------------

R_poly = sg.PolynomialRing(sg.IntegerModRing(Q), 'x')   # Z_q[x]
x = R_poly.gen()
Rq = R_poly.quotient(x ** N + 1)                        # R_q = Z_q[x]/(x^N+1)
