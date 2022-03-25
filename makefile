.PHONY : dist clean

VERSION = 5.5.0
DIR_NAME := pdfcrowd-5.5.0

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
	@mvn deploy
	@echo To publish staging repository use Close on https://oss.sonatype.org/#stagingRepositories
