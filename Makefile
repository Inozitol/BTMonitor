IDIR=./include
ODIR=./obj
SDIR=./src

SRC=main.cpp bt-dht-regex.cpp bt-dns-regex.cpp bt-pp-regex.cpp flow-analyzer.cpp flow-keys-types.cpp flow-types.cpp thread-killer.cpp utils.cpp
_OBJ=$(SRC:%.cpp=%.o)
OBJ=$(patsubst %,$(ODIR)/%,$(_OBJ))

TRG=BTMonitor
CC=g++
LIB=-lpcap -lpthread
FLG=-I$(IDIR)

$(TRG): $(ODIR) build

$(ODIR):
	mkdir -p $@

build: $(OBJ)
	$(CC) -o $(TRG) $^ $(LIB) $(FLG)

$(ODIR)/%.o: $(SDIR)/%.cpp
	$(CC) -c -o $@ $< $(FLG)

.PHONY: clean
clean:
	rm -f $(TRG)
	rm -rf $(ODIR)
