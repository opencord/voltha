default: test

build:
	protoc -I . --python_out=. ext1.proto
	protoc -I . --python_out=. ext2.proto

test: build
	./write_generic.py | ./read_generic.py
	./write_generic.py | ./read_ext1.py
	./write_generic.py | ./read_ext2.py
	./write_generic.py | ./read_both.py

	./write_ext1.py | ./read_generic.py
	./write_ext1.py | ./read_ext1.py
	./write_ext1.py | ./read_ext2.py
	./write_ext1.py | ./read_both.py

	./write_ext2.py | ./read_generic.py
	./write_ext2.py | ./read_ext1.py
	./write_ext2.py | ./read_ext2.py
	./write_ext2.py | ./read_both.py

