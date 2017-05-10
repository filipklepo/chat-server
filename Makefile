TARGET = chat
OBJECTS = chat-server.o mrepro.o

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS)

clean:
	rm $(TARGET) $(OBJECTS)
