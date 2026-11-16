.PHONY: help build ipa scenarios profile identities collect verdict check-report log selftest clean

IDENTITY ?=
TEAM     ?=
REAL_PROFILE ?=
LOGFILE  ?= amfi.log

help:
	@echo "make build            build the unsigned iOS app and IPA (macOS only)"
	@echo "make scenarios        build the signed variant matrix"
	@echo "make identities       list every signing identity and its Apple class"
	@echo "make collect          pull the accumulated report off the device"
	@echo "make verdict          print the verdict table"
	@echo "make log              capture the kernel's AMFI lines (Mac, device attached)"
	@echo "make selftest         run the local checks (no device, no macOS needed)"
	@echo "make clean            remove build output"
	@echo
	@echo "  scenarios: make scenarios IDENTITY='Apple Development: YOU' TEAM=TEAMID"
	@echo "  verdict:   make verdict LOGFILE=amfi.log"

build:
	./scripts/build_ios.sh

ipa: build

scenarios:
	@test -n "$(IDENTITY)" || (echo "usage: make scenarios IDENTITY=\"Apple Development: YOU\" TEAM=TEAMID" && exit 2)
	./scripts/scenarios.sh --identity "$(IDENTITY)" --team "$(TEAM)" \
		$(if $(REAL_PROFILE),--real-profile "$(REAL_PROFILE)",)

profile:
	python3 scripts/make_profile.py --out out/profile.plist \
		--entitlement com.apple.private.mobileinstall.allowedSPI \
		--entitlement com.apple.private.security.no-sandbox \
		--apple-internal
	@cat out/profile.plist

identities:
	python3 scripts/identity_classes.py

cert-class:
	@test -n "$(f)" || (echo "usage: make cert-class f=Profile.mobileprovision" && exit 2)
	python3 scripts/cert_class.py "$(f)"

collect:
	./scripts/collect.sh

verdict:
	@test -f reports/probe-report.txt || (echo "no report yet — run 'make collect'" && exit 2)
	python3 scripts/verdict.py reports/probe-report.txt \
		$(if $(wildcard $(LOGFILE)),--log $(LOGFILE),)

check-report:
	@test -n "$(f)" || (echo "usage: make check-report f=probe-report.txt" && exit 2)
	python3 scripts/parse_report.py $(f)

log:
	log show --last 30m --predicate 'process == "amfid" OR eventMessage CONTAINS[c] "AMFI"' > $(LOGFILE)
	@echo "wrote $(LOGFILE)"

selftest:
	python3 -m py_compile scripts/make_profile.py scripts/verdict.py scripts/parse_report.py scripts/execsegflags.py
	@echo "python: ok"
	@bash -n scripts/build_ios.sh scripts/scenarios.sh scripts/collect.sh && echo "shell: ok"
	@python3 scripts/selftest.py

clean:
	rm -rf out reports
