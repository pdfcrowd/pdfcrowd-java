.PHONY : dist clean

VERSION = 6.5.2
DIR_NAME := pdfcrowd-6.5.2

compile:
	@mvn clean verify

clean:
	@rm -rf dist

dist: dist/pdfcrowd-$(VERSION)-java.zip

dist/pdfcrowd-$(VERSION)-java.zip:
	@mkdir -p dist
	@cd dist && mkdir -p $(DIR_NAME) && cp ../target/pdfcrowd*.jar $(DIR_NAME) && zip pdfcrowd-$(VERSION)-java.zip $(DIR_NAME)/* $(DIR_NAME)/*

publish: clean compile dist
	@mvn install
	@mvn deploy -P release
	@echo To publish staging repository use Close on https://oss.sonatype.org/#stagingRepositories
