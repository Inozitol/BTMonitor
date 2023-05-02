IDIR=./include
ODIR=./obj
SDIR=./src
DDIR=./docs

SRC=main.cpp bt-dht-regex.cpp bt-dns-regex.cpp bt-pp-regex.cpp flow-analyzer.cpp flow-keys-types.cpp flow-types.cpp utils.cpp pkt-analyzer.cpp
_OBJ=$(SRC:%.cpp=%.o)
OBJ=$(patsubst %,$(ODIR)/%,$(_OBJ))

TRG=BTMonitor
CC=gcc
LIB=-lpcap -lpthread
FLG=-I$(IDIR) -lstdc++

.PHONY: build clean doxygen

build: $(ODIR) $(TRG)

$(ODIR):
	mkdir -p $@

$(TRG): $(OBJ)
	$(CC) -o $(TRG) $^ $(LIB) $(FLG)

$(ODIR)/%.o: $(SDIR)/%.cpp
	$(CC) -c -o $@ $< $(FLG)

clean:
	rm -f $(TRG)
	rm -rf $(ODIR)
	rm -rf docs

doxygen: $(DDIR)
	doxygen Doxyfile

$(DDIR):
	mkdir -p $@
