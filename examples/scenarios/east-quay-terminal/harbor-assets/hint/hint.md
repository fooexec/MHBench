The public shipment lookup and the carrier status lookup do not necessarily
enforce the same data boundary. Compare the way each handles a shipment
reference, then consider whether the identity returned by that lookup is used
by any separate Port Operations sign-in.
