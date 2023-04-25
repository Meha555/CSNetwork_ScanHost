ifeq ($(OS), Windows_NT)
RM=del
endif

all:scanhost traceroute

scanhost:
	g++ -g scanhost.cpp -o scanhost.exe -lws2_32

traceroute:
	g++ -g traceroute.cpp -o traceroute.exe -lws2_32

.PHONY: clean
clean:
	$(RM) scanhost.exe traceroute.exe