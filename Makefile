CC      = clang
CFLAGS  = -std=c11 -Wall -O2
LDFLAGS = -framework IOKit -framework CoreFoundation -lutil
TARGET  = qcseriald
SRC     = qcseriald.c

PREFIX  ?= /usr/local
PLIST   = com.iamromulan.qcseriald.plist

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/$(TARGET)
	install -m 644 $(PLIST) /Library/LaunchDaemons/$(PLIST)
	@echo ""
	@echo "Installed binary to $(PREFIX)/bin/$(TARGET)"
	@echo "Installed launchd plist to /Library/LaunchDaemons/$(PLIST)"
	@echo ""
	@echo "To enable auto-start:"
	@echo "  sudo launchctl load /Library/LaunchDaemons/$(PLIST)"
	@echo ""
	@echo "To start manually:"
	@echo "  sudo qcseriald start"

uninstall:
	launchctl unload /Library/LaunchDaemons/$(PLIST) 2>/dev/null || true
	rm -f $(PREFIX)/bin/$(TARGET)
	rm -f /Library/LaunchDaemons/$(PLIST)
	@echo "Uninstalled."

clean:
	rm -f $(TARGET)
