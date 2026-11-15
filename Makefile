.PHONY: help build ipa profile check-report clean

help:
	@echo "make ipa            build the unsigned iOS app and IPA (macOS only)"
	@echo "make profile        print the crafted provisioning profile"
	@echo "make check-report   summarise a device report: make check-report f=probe-report.txt"
	@echo "make clean          remove build output"

build:
	./scripts/build_ios.sh

ipa: build

profile:
	python3 scripts/make_profile.py --out out/profile.plist \
		--entitlement com.apple.private.mobileinstall.allowedSPI \
		--entitlement com.apple.private.security.no-sandbox \
		--apple-internal
	@cat out/profile.plist

check-report:
	@test -n "$(f)" || (echo "usage: make check-report f=<report.txt>" && exit 2)
	python3 scripts/parse_report.py $(f)

clean:
	rm -rf out
