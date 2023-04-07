SRC=main.cpp bt-dht-regex.cpp bt-dns-regex.cpp bt-pp-regex.cpp flow-analyzer.cpp flow-keys-types.cpp flow-types.cpp thread-killer.cpp utils.cpp
OBJ=$(SRC:%.cpp=$.o)
TRG=BTMonitor
CC=gcc
LIB=-lpcap
FLG=

.PHONY: all
all: $(TRG)

%.o: $(SRC)
	$(CC) -c -o $@ $< $(FLG)

$(TRG): $(OBJ)
	$(CC) -o $@ $^ $(LIB) $(FLG)
