This is an experiment to work with Any type fields in protobuf and
in Python. Run 'make' to see how a set of writers emit data with
no or one of two extensions, while four readers try to decode the
data. Depending on which of them pre-loads the extension protobufs,
they can decode the extension data or leave it in the packed value
format.
