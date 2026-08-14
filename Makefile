.PHONY: ui build test check check-race clean dev-ui all install uninstall

BINARY   = mcxas
VERSION  = 0.0.1d
PREFIX   = /opt/vectorcore
BINDIR   = $(PREFIX)/bin
ETCDIR   = $(PREFIX)/etc
LOGDIR   = $(PREFIX)/log
LOGFILE  = $(PREFIX)/mcxas.log
SYSTEMD  = /lib/systemd/system/
CONFSRC  = config/config.yaml
# Unprivileged account the service runs as; see systemd/vectorcore-mcxas.service.
SVCUSER  = vectorcore
SVCGROUP = vectorcore

all: ui build

# Build the React UI (required before `make build` for the production UI)
ui:
	cd web && ([ -f package-lock.json ] && npm ci || npm install) && npm run build

# Build the Go binary (embeds web/dist if present)
build:
	go build -buildvcs=false -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) ./cmd/mcxas

test:
	go test ./...

# Full pre-commit gate: build, vet, format-drift (fails on any), and tests.
check:
	go build ./...
	go vet ./...
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt drift:"; echo "$$unformatted"; exit 1; fi
	go test ./...

# check plus the race detector. Needs a C compiler (CGO). On the Windows dev
# machine gcc lives at %USERPROFILE%\sdk\mingw64\bin; on Linux it is packaged.
# Fails with a clear message rather than silently skipping when CGO is off.
check-race: check
	@if [ "$$(go env CGO_ENABLED)" != "1" ] && ! command -v gcc >/dev/null 2>&1; then \
		echo "check-race needs a C compiler; put gcc on PATH and set CGO_ENABLED=1"; exit 1; \
	fi
	CGO_ENABLED=1 go test -race ./...

# Start Vite dev server (proxies API to localhost:8080)
dev-ui:
	cd web && npm run dev

clean:
	rm -rf bin/ web/dist/

# Requires root. Creates the unprivileged service account if absent, then
# installs the binary, configuration and unit file under $(PREFIX). The
# configuration may carry a database password so it is not world readable,
# and the service account owns everything the daemon has to write.
install: build
	@getent group $(SVCGROUP) >/dev/null || groupadd --system $(SVCGROUP)
	@getent passwd $(SVCUSER) >/dev/null || \
		useradd --system --gid $(SVCGROUP) --home-dir $(PREFIX) \
			--shell /usr/sbin/nologin --comment "VectorCore MCX" $(SVCUSER)
	install -d $(BINDIR)
	install -d $(ETCDIR)
	install -d $(LOGDIR)
	install -m755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	@if [ ! -f $(ETCDIR)/mcxas.yaml ]; then \
		install -m640 $(CONFSRC) $(ETCDIR)/mcxas.yaml; \
	fi
	touch $(LOGFILE)
	chown -R $(SVCUSER):$(SVCGROUP) $(PREFIX)
	chmod 750 $(PREFIX)
	chmod 640 $(ETCDIR)/mcxas.yaml
	chmod 640 $(LOGFILE)
	install -d /lib/systemd/system
	install -m644 systemd/vectorcore-mcxas.service $(SYSTEMD)/vectorcore-mcxas.service
	systemctl daemon-reload
	systemctl enable vectorcore-mcxas
	systemctl start vectorcore-mcxas

uninstall:
	systemctl stop vectorcore-mcxas || true
	systemctl disable vectorcore-mcxas || true
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(SYSTEMD)/vectorcore-mcxas.service
	systemctl daemon-reload
