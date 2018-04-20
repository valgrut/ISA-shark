PROJ=isashark
FLAGS=-std=c++14 -Wall -Wextra -Weffc++
CC=g++

main: $(PROJ).cpp $(PROJ).h
	$(CC) $(FLAGS) $(PROJ).cpp -o $(PROJ) -lpcap
