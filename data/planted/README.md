# Planted file for module C (DSPM)

`vendor-payments-export.csv` is deliberately "sensitive" and is uploaded by `dspm/classify.py plant`
with the WRONG label (`sensitivity=public`). Every value is fake: the card numbers are the public
test numbers payment processors publish for testing, and the SSNs and bank account numbers are
invented. Nothing here belongs to a real person.
